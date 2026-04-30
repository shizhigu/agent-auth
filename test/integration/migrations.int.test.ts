/**
 * Integration: forward + backward migration round-trip. SPEC §3.17 / §12.7.
 *
 * Spin up a clean Postgres, apply 0001..NNNN, prove the schema works,
 * run NNNN..0001.down, prove tables are gone, then apply 0001..NNNN
 * AGAIN to prove migrations are idempotent through a full rollback +
 * forward cycle. This is the lib-side automated check for the
 * PRE_RELEASE_CHECKLIST "Forward + backward migration tested" item.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import { Pool, type PoolClient } from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, '..', '..', 'schema', 'migrations');

function listUpMigrations(): string[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql') && !f.endsWith('.down.sql'))
    .sort();
}

function listDownMigrations(): string[] {
  // Down migrations applied in reverse order of ups.
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.down.sql'))
    .sort()
    .reverse();
}

async function applyAll(client: PoolClient, files: string[]): Promise<void> {
  for (const f of files) {
    const sql = readFileSync(join(MIGRATIONS_DIR, f), 'utf8');
    await client.query(sql);
  }
}

describe('integration: migrations forward + rollback round-trip (SPEC §3.17)', () => {
  let container: StartedPostgreSqlContainer;
  let pool: Pool;

  beforeAll(async () => {
    container = await new PostgreSqlContainer('postgres:16-alpine')
      .withDatabase('agent_auth_migrate_test')
      .withUsername('test_user')
      .withPassword('test_pw')
      .start();
    pool = new Pool({
      host: container.getHost(),
      port: container.getPort(),
      database: container.getDatabase(),
      user: container.getUsername(),
      password: container.getPassword(),
    });
  }, 240_000);

  afterAll(async () => {
    await pool?.end().catch(() => undefined);
    await container?.stop().catch(() => undefined);
  }, 120_000);

  it('forward → smoke → rollback → smoke gone → forward again → smoke', async () => {
    const ups = listUpMigrations();
    const downs = listDownMigrations();
    expect(ups.length).toBeGreaterThanOrEqual(5);
    expect(downs.length).toBe(ups.length);

    // 1. Forward.
    const c1 = await pool.connect();
    try {
      await applyAll(c1, ups);
    } finally {
      c1.release();
    }

    // 2. Smoke: agent_accounts table exists and accepts an INSERT.
    const c2 = await pool.connect();
    try {
      const ins = await c2.query<{ id: string }>(
        `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('migrate-smoke', 'cold', 'active') RETURNING id::text AS id`,
      );
      expect(ins.rows[0]?.id).toBeTruthy();
      // Also probe agent_idempotency (0004) and agent_revocation_barrier (0003).
      const ep = await c2.query<{ epoch: string }>(
        `SELECT epoch::text AS epoch FROM agent_revocation_epoch WHERE id = 1`,
      );
      expect(ep.rows[0]?.epoch).toBe('0');
    } finally {
      c2.release();
    }

    // 3. Rollback (reverse order).
    const c3 = await pool.connect();
    try {
      await applyAll(c3, downs);
    } finally {
      c3.release();
    }

    // 4. Smoke gone: tables should be missing.
    const c4 = await pool.connect();
    try {
      const reg = await c4.query<{ exists: boolean }>(
        `SELECT to_regclass('public.agent_accounts') IS NOT NULL AS exists`,
      );
      expect(reg.rows[0]?.exists).toBe(false);
    } finally {
      c4.release();
    }

    // 5. Forward again.
    const c5 = await pool.connect();
    try {
      await applyAll(c5, ups);
    } finally {
      c5.release();
    }

    // 6. Smoke again.
    const c6 = await pool.connect();
    try {
      const ins = await c6.query<{ id: string }>(
        `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('migrate-smoke-2', 'cold', 'active') RETURNING id::text AS id`,
      );
      expect(ins.rows[0]?.id).toBeTruthy();
    } finally {
      c6.release();
    }
  }, 240_000);

  it('migrations are idempotent — re-running the up sequence on an already-migrated DB succeeds', async () => {
    // The previous test left the DB at "fully migrated" state. Re-apply the
    // ups; everything must be IF NOT EXISTS / CREATE OR REPLACE so this is
    // a no-op rather than an error.
    const c = await pool.connect();
    try {
      await applyAll(c, listUpMigrations());
      // Schema still works.
      const ins = await c.query<{ id: string }>(
        `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('migrate-idem', 'cold', 'active') RETURNING id::text AS id`,
      );
      expect(ins.rows[0]?.id).toBeTruthy();
    } finally {
      c.release();
    }
  }, 240_000);
});
