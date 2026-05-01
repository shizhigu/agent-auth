/**
 * Migration runner — applies / rolls back the SQL files Vouch ships in
 * `agent-auth/schema/migrations/`. Tracking lives in a `vouch_migrations`
 * table so re-running is idempotent.
 *
 * Each file is wrapped in a transaction. If a migration fails partway, the
 * transaction rolls back and the version is NOT recorded — re-running picks
 * up where we left off.
 *
 * Naming convention (mirrors what's in the lib's schema/migrations/):
 *
 *   0001_init.sql        -- forward
 *   0001_init.down.sql   -- rollback (optional but recommended)
 *
 * Sort key is the `<NNNN>` prefix — a four-digit zero-padded version. The
 * prefix is parsed lexically; we don't try to interpret it as a number,
 * so `0001` < `0002` < `0010` works as expected.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Pool, PoolClient } from 'pg';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Migration {
  /** Lexical version (e.g. `0006`). */
  readonly version: string;
  /** Filename minus the `.sql` extension (e.g. `0006_recover_pending_approval`). */
  readonly name: string;
  /** Absolute path to the forward SQL. */
  readonly up_path: string;
  /** Absolute path to the rollback SQL, if one exists. */
  readonly down_path: string | null;
}

export interface MigrationResult {
  readonly version: string;
  readonly name: string;
  readonly direction: 'up' | 'down';
  readonly duration_ms: number;
}

export interface MigrationStatus {
  readonly applied: ReadonlyArray<{ version: string; applied_at: Date }>;
  readonly pending: ReadonlyArray<Migration>;
}

export interface MigrateRunner {
  list(): Migration[];
  status(): Promise<MigrationStatus>;
  up(opts?: { to?: string; dryRun?: boolean }): Promise<MigrationResult[]>;
  down(opts?: { steps?: number; dryRun?: boolean }): Promise<MigrationResult[]>;
}

export interface MigrateRunnerConfig {
  /** Postgres pool. The runner does NOT close it on its own. */
  readonly pool: Pool;
  /** Directory containing `NNNN_*.sql` files. Defaults to the bundled lib's. */
  readonly schema_dir: string;
  /** Tracking table name. Default `vouch_migrations`. */
  readonly tracking_table?: string;
  /** Optional logger. Defaults to console.log via `process.stderr`. */
  readonly logger?: (line: string) => void;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

const DEFAULT_TRACKING_TABLE = 'vouch_migrations';

export function createMigrateRunner(cfg: MigrateRunnerConfig): MigrateRunner {
  const tableName = cfg.tracking_table ?? DEFAULT_TRACKING_TABLE;
  // Defense-in-depth: validate the tracking table name eagerly. quoteIdent
  // would catch a bad name later but only after we've opened a connection.
  validateIdent(tableName);
  const log = cfg.logger ?? ((line) => process.stderr.write(line + '\n'));

  function listSync(): Migration[] {
    let entries: string[];
    try {
      entries = readdirSync(cfg.schema_dir);
    } catch (err) {
      throw new Error(
        `Cannot read schema dir ${cfg.schema_dir}: ${(err as Error).message}`,
      );
    }
    const ups = entries.filter((e) => /^\d{4}.+\.sql$/.test(e) && !e.endsWith('.down.sql')).sort();
    const result: Migration[] = [];
    for (const filename of ups) {
      const match = /^(\d{4})_(.+)\.sql$/.exec(filename);
      if (!match) continue;
      const [, version, restPart] = match;
      if (!version || !restPart) continue;
      const name = `${version}_${restPart}`;
      const up_path = join(cfg.schema_dir, filename);
      const downCandidate = join(cfg.schema_dir, `${name}.down.sql`);
      let down_path: string | null = null;
      try {
        statSync(downCandidate);
        down_path = downCandidate;
      } catch {
        // no down file — that's fine, we just can't roll back this one.
      }
      result.push({ version, name, up_path, down_path });
    }
    return result;
  }

  async function ensureTrackingTable(client: PoolClient): Promise<void> {
    await client.query(`
      CREATE TABLE IF NOT EXISTS ${quoteIdent(tableName)} (
        version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
  }

  async function getApplied(client: PoolClient): Promise<Map<string, Date>> {
    await ensureTrackingTable(client);
    const { rows } = await client.query<{ version: string; applied_at: Date }>(
      `SELECT version, applied_at FROM ${quoteIdent(tableName)} ORDER BY version`,
    );
    return new Map(rows.map((r) => [r.version, r.applied_at]));
  }

  return {
    list: listSync,

    async status() {
      const all = listSync();
      const client = await cfg.pool.connect();
      try {
        const applied = await getApplied(client);
        const pending = all.filter((m) => !applied.has(m.version));
        return {
          applied: [...applied.entries()].map(([version, applied_at]) => ({
            version,
            applied_at,
          })),
          pending,
        };
      } finally {
        client.release();
      }
    },

    async up(opts = {}) {
      const all = listSync();
      const results: MigrationResult[] = [];
      const client = await cfg.pool.connect();
      try {
        const applied = await getApplied(client);
        for (const m of all) {
          if (applied.has(m.version)) continue;
          if (opts.to !== undefined && m.version > opts.to) break;
          const sql = readFileSync(m.up_path, 'utf8');
          if (opts.dryRun) {
            log(`[dry-run] would apply ${m.name}`);
            continue;
          }
          log(`-> ${m.name} (up)`);
          const t0 = Date.now();
          await client.query('BEGIN');
          try {
            await client.query(sql);
            await client.query(
              `INSERT INTO ${quoteIdent(tableName)} (version, name) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`,
              [m.version, m.name],
            );
            await client.query('COMMIT');
          } catch (err) {
            await client.query('ROLLBACK');
            throw new Error(
              `Migration ${m.name} failed at ${m.up_path}: ${(err as Error).message}`,
              { cause: err },
            );
          }
          results.push({
            version: m.version,
            name: m.name,
            direction: 'up',
            duration_ms: Date.now() - t0,
          });
        }
      } finally {
        client.release();
      }
      return results;
    },

    async down(opts = {}) {
      const steps = Math.max(1, opts.steps ?? 1);
      const all = listSync();
      const byVersion = new Map(all.map((m) => [m.version, m]));
      const results: MigrationResult[] = [];
      const client = await cfg.pool.connect();
      try {
        const applied = await getApplied(client);
        const reverseApplied = [...applied.keys()].sort().reverse();
        for (let i = 0; i < steps && i < reverseApplied.length; i++) {
          const version = reverseApplied[i];
          if (!version) break;
          const m = byVersion.get(version);
          if (!m) {
            throw new Error(
              `Migration ${version} is recorded as applied but no SQL file is present in ${cfg.schema_dir}`,
            );
          }
          if (!m.down_path) {
            throw new Error(
              `Migration ${m.name} has no .down.sql — cannot roll back automatically. Drop it manually if needed.`,
            );
          }
          const sql = readFileSync(m.down_path, 'utf8');
          if (opts.dryRun) {
            log(`[dry-run] would roll back ${m.name}`);
            continue;
          }
          log(`-> ${m.name} (down)`);
          const t0 = Date.now();
          await client.query('BEGIN');
          try {
            await client.query(sql);
            await client.query(
              `DELETE FROM ${quoteIdent(tableName)} WHERE version = $1`,
              [m.version],
            );
            await client.query('COMMIT');
          } catch (err) {
            await client.query('ROLLBACK');
            throw new Error(
              `Rollback ${m.name} failed at ${m.down_path}: ${(err as Error).message}`,
              { cause: err },
            );
          }
          results.push({
            version: m.version,
            name: m.name,
            direction: 'down',
            duration_ms: Date.now() - t0,
          });
        }
      } finally {
        client.release();
      }
      return results;
    },
  };
}

/**
 * Resolve the bundled schema directory shipped with the `@vouch/server`
 * lib. Uses node_modules resolution so this works whether the CLI is
 * installed via npm, linked from a workspace, or run from a fresh
 * checkout.
 */
export function resolveBundledSchemaDir(): string {
  // Defer the import so `createMigrateRunner` callers that pass their own
  // schema_dir (e.g. tests) don't have to have @vouch/server installed.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createRequire } = require('node:module') as typeof import('node:module');
  const { dirname, join } = require('node:path') as typeof import('node:path');
  const req = createRequire(import.meta.url);
  const pkgPath = req.resolve('@vouch/server/package.json');
  return join(dirname(pkgPath), 'schema', 'migrations');
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function quoteIdent(name: string): string {
  validateIdent(name);
  return `"${name}"`;
}

function validateIdent(name: string): void {
  // Whitelist: alphanumeric + underscore. Anything else is rejected.
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name)) {
    throw new Error(`Invalid identifier: ${name}`);
  }
}
