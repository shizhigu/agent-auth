/**
 * Postgres adapter — thin wrapper around `pg.Pool` that pins
 * `application_name`, exposes role-aware connections, and centralizes
 * common query patterns (queryOne, transaction, role assertion).
 *
 * SPEC §3.16 (roles), §4.3 (Tier B commit timeout — caller wraps), §11.5.
 *
 * Roles:
 *   - app: the regular pool used by the lib's hot path. NOLOGIN role granted
 *     to a LOGIN user; pool connection sets `SET ROLE agent_auth_app` on
 *     each checkout (idempotent).
 *   - admin: separate pool used only by the admin CLI / two-person tools.
 *   - migrator: separate pool used by `agent-auth migrate`.
 */

import { Pool } from 'pg';
import type { PoolClient, PoolConfig, QueryResultRow } from 'pg';

export type AppRole =
  | 'agent_auth_app'
  | 'agent_auth_admin'
  | 'agent_auth_readonly'
  | 'agent_auth_migrator';

export interface PostgresAdapterConfig {
  /** pg.Pool config; the lib augments it with role + application_name pinning. */
  readonly pool: PoolConfig;
  /** Role to SET on each checkout. Default: agent_auth_app. */
  readonly role?: AppRole;
  /** Custom application_name (shows up in pg_stat_activity). */
  readonly application_name?: string;
}

export interface QueryOptions {
  /** Statement timeout in ms (sets `SET LOCAL statement_timeout`). */
  readonly statement_timeout_ms?: number;
}

const ALLOWED_ROLES: ReadonlySet<AppRole> = new Set<AppRole>([
  'agent_auth_app',
  'agent_auth_admin',
  'agent_auth_readonly',
  'agent_auth_migrator',
]);

export class PostgresAdapter {
  private readonly pool: Pool;
  private readonly role: AppRole;
  private readonly applicationName: string;

  constructor(cfg: PostgresAdapterConfig) {
    const role = cfg.role ?? 'agent_auth_app';
    // Defense in depth (SPEC §3.16): the role is interpolated into
    // `SET ROLE ${role}` on every checkout, so a misconfigured value
    // (e.g. via `as any`) could SQL-inject. The TypeScript type is the
    // primary gate; this runtime check stops anything that slipped past
    // a `cfg as PostgresAdapterConfig` cast.
    if (!ALLOWED_ROLES.has(role)) {
      throw new Error(`PostgresAdapter: role must be one of ${[...ALLOWED_ROLES].join(', ')}`);
    }
    this.role = role;
    this.applicationName = cfg.application_name ?? `agent-auth/${this.role}`;
    this.pool = new Pool({
      ...cfg.pool,
      application_name: this.applicationName,
    });
  }

  /**
   * Acquire a client and pin its role. Returns a disposable handle — caller
   * MUST call .release() in a finally block (or use `withClient`).
   */
  async acquire(): Promise<PoolClient> {
    const client = await this.pool.connect();
    try {
      await client.query(`SET ROLE ${this.role}`);
    } catch (err) {
      client.release();
      throw err;
    }
    return client;
  }

  /** Run `fn` with a checked-out client; release in finally. */
  async withClient<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.acquire();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  /**
   * Run `fn` inside `BEGIN/COMMIT`. Rolls back on throw. Returns whatever
   * `fn` returns. The caller MUST NOT issue BEGIN/COMMIT/ROLLBACK manually.
   */
  async transaction<T>(
    fn: (client: PoolClient) => Promise<T>,
    opts?: { readonly isolation?: 'READ COMMITTED' | 'REPEATABLE READ' | 'SERIALIZABLE' },
  ): Promise<T> {
    return this.withClient(async (client) => {
      const iso = opts?.isolation ?? 'READ COMMITTED';
      await client.query(`BEGIN ISOLATION LEVEL ${iso}`);
      try {
        const out = await fn(client);
        await client.query('COMMIT');
        return out;
      } catch (err) {
        try {
          await client.query('ROLLBACK');
        } catch {
          // ignore — surface the original error
        }
        throw err;
      }
    });
  }

  async query<R extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: ReadonlyArray<unknown>,
    options?: QueryOptions,
  ): Promise<{ rows: R[]; rowCount: number }> {
    if (options?.statement_timeout_ms !== undefined) {
      // SET LOCAL only applies inside a transaction. Wrap so the timeout is
      // scoped to the single statement and unaffected by other pool users.
      const ms = Math.max(1, Math.floor(options.statement_timeout_ms));
      return this.withClient(async (client) => {
        await client.query('BEGIN');
        try {
          await client.query(`SET LOCAL statement_timeout = ${ms}`);
          const res = await client.query<R>(text, params as unknown[]);
          await client.query('COMMIT');
          return { rows: res.rows, rowCount: res.rowCount ?? 0 };
        } catch (err) {
          await client.query('ROLLBACK').catch(() => undefined);
          throw err;
        }
      });
    }
    return this.withClient(async (client) => {
      const res = await client.query<R>(text, params as unknown[]);
      return { rows: res.rows, rowCount: res.rowCount ?? 0 };
    });
  }

  /**
   * queryOne — returns the first row or null. Throws if multiple rows match.
   */
  async queryOne<R extends QueryResultRow = QueryResultRow>(
    text: string,
    params?: ReadonlyArray<unknown>,
    options?: QueryOptions,
  ): Promise<R | null> {
    const { rows } = await this.query<R>(text, params, options);
    if (rows.length === 0) return null;
    if (rows.length > 1) {
      throw new Error(`queryOne returned ${rows.length} rows`);
    }
    return rows[0] ?? null;
  }

  /** Drain in-flight queries and close pool. Call on graceful shutdown. */
  async close(): Promise<void> {
    await this.pool.end();
  }

  /** Test-only: assert which role a connection inherits. */
  async assertCurrentRole(): Promise<AppRole> {
    const row = await this.queryOne<{ current_user: string }>(
      'SELECT current_user::text AS current_user',
    );
    if (!row) throw new Error('current_user query returned no row');
    return row.current_user as AppRole;
  }
}
