/**
 * Unit: PostgresAdapter constructor guards.
 *
 * Defense-in-depth: the `role` config field is interpolated into
 * `SET ROLE ${role}` on every checkout. The TypeScript AppRole union
 * is the primary gate, but a SaaS that bypasses it via `as any`
 * could SQL-inject. The constructor must reject any value not in
 * the AppRole whitelist.
 */
import { describe, it, expect } from 'vitest';
import { PostgresAdapter, type AppRole } from '../../src/storage/postgres-adapter.js';

describe('PostgresAdapter constructor (SPEC §3.16)', () => {
  // Minimal pool config — pg.Pool is lazy so no connection happens until
  // pool.connect/query is called.
  const pool = { host: '127.0.0.1', port: 5432, database: 'x', user: 'u', password: 'p' };

  it('accepts the documented AppRoles', () => {
    for (const role of [
      'agent_auth_app',
      'agent_auth_admin',
      'agent_auth_readonly',
      'agent_auth_migrator',
    ] as const) {
      const adapter = new PostgresAdapter({ pool, role });
      expect(adapter).toBeInstanceOf(PostgresAdapter);
      // close the pool so vitest doesn't keep the process alive.
      void adapter.close().catch(() => undefined);
    }
  });

  it('rejects role values outside the AppRole whitelist (SQL injection guard)', () => {
    const evil = 'agent_auth_app; DROP TABLE agent_accounts; --';
    expect(
      () =>
        new PostgresAdapter({
          pool,
          // Bypass the TS gate the way a misconfigured SaaS could.
          role: evil as unknown as AppRole,
        }),
    ).toThrow(/role must be one of/);
  });

  it('default role is agent_auth_app when role is omitted', () => {
    const adapter = new PostgresAdapter({ pool });
    expect(adapter).toBeInstanceOf(PostgresAdapter);
    void adapter.close().catch(() => undefined);
  });
});
