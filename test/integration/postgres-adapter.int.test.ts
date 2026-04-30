/**
 * Integration: PostgresAdapter behavior against a real database.
 * Verifies SPEC §3.16 role-aware connections, §4.3 statement timeout
 * scoping, and the transaction rollback contract.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

describe('integration: PostgresAdapter (SPEC §3.16 / §4.3)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('SET ROLE pins the configured role per checkout', async () => {
    expect(await fix.postgres.assertCurrentRole()).toBe('agent_auth_app');
    const admin = new PostgresAdapter({
      pool: {
        host: fix.pg_container.getHost(),
        port: fix.pg_container.getPort(),
        database: fix.pg_container.getDatabase(),
        user: fix.pg_container.getUsername(),
        password: fix.pg_container.getPassword(),
      },
      role: 'agent_auth_admin',
    });
    expect(await admin.assertCurrentRole()).toBe('agent_auth_admin');
    await admin.close();
  });

  it('transaction commits on success', async () => {
    const acc = await fix.postgres.transaction(async (client) => {
      const out = await client.query<{ id: string }>(
        `INSERT INTO agent_accounts (display_handle, tier, status)
           VALUES ('txn-commit', 'cold', 'active') RETURNING id`,
      );
      return out.rows[0]!.id;
    });
    const row = await fix.postgres.queryOne<{ id: string }>(
      `SELECT id::text AS id FROM agent_accounts WHERE display_handle = 'txn-commit'`,
    );
    expect(row?.id).toBe(acc);
  });

  it('transaction rolls back on throw', async () => {
    let caught: unknown;
    try {
      await fix.postgres.transaction(async (client) => {
        await client.query(
          `INSERT INTO agent_accounts (display_handle, tier, status)
             VALUES ('txn-rollback', 'cold', 'active')`,
        );
        throw new Error('intentional');
      });
    } catch (err) {
      caught = err;
    }
    expect((caught as Error).message).toBe('intentional');
    const row = await fix.postgres.queryOne<{ id: string }>(
      `SELECT id::text AS id FROM agent_accounts WHERE display_handle = 'txn-rollback'`,
    );
    expect(row).toBeNull();
  });

  it('statement_timeout caps a slow query', async () => {
    let caught: unknown;
    try {
      await fix.postgres.query(
        `SELECT pg_sleep(5)`,
        [],
        { statement_timeout_ms: 100 },
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    const e = caught as { code?: string };
    // Postgres error 57014 — query_canceled (statement timeout fired).
    expect(e.code).toBe('57014');
  });

  it('queryOne throws on multi-row result', async () => {
    await fix.postgres.transaction(async (client) => {
      await client.query(
        `INSERT INTO agent_accounts (display_handle, tier, status)
           VALUES ('multi-1', 'cold', 'active'), ('multi-2', 'cold', 'active')`,
      );
    });
    let caught: unknown;
    try {
      await fix.postgres.queryOne(
        `SELECT id FROM agent_accounts WHERE display_handle LIKE 'multi-%'`,
      );
    } catch (err) {
      caught = err;
    }
    expect((caught as Error).message).toMatch(/queryOne/);
  });
});
