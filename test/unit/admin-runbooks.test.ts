/**
 * Unit: rbAuditTail handler (SPEC §8.2 / RB-6).
 *
 * Default 24h window + limit 100; filters compose with account_id,
 * key_id, event_type. Hard cap at 10_000 prevents DoS via runaway query.
 */
import { describe, it, expect } from 'vitest';
import { rbAuditTail } from '../../src/admin/runbooks.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { AdminDispatchDeps } from '../../src/admin/cli.js';

class FakePg {
  capturedSql = '';
  capturedParams: ReadonlyArray<unknown> = [];
  rows: Array<Record<string, unknown>> = [];
  async query<R>(text: string, params?: ReadonlyArray<unknown>) {
    this.capturedSql = text;
    this.capturedParams = params ?? [];
    return { rows: this.rows as unknown as R[], rowCount: this.rows.length };
  }
}

function makeDeps(pg: FakePg): AdminDispatchDeps {
  return {
    postgres: pg as unknown as PostgresAdapter,
  } as unknown as AdminDispatchDeps;
}

const baseInput = {
  command: 'audit-tail' as const,
  admin_id: 'admin@saas',
  jit_grant_id: 'g_x',
  reason: 'incident-2026-04-30',
};

describe('rbAuditTail (SPEC §8.2 / RB-6)', () => {
  it('default since=24h, limit=100', async () => {
    const pg = new FakePg();
    const handler = rbAuditTail();
    const before = Date.now();
    await handler.run({ ...baseInput, options: {} }, makeDeps(pg));
    const after = Date.now();
    expect(pg.capturedParams).toHaveLength(2); // since + limit
    const since = pg.capturedParams[0] as Date;
    const limit = pg.capturedParams[1] as number;
    expect(since.getTime()).toBeGreaterThanOrEqual(before - 24 * 3600 * 1000 - 100);
    expect(since.getTime()).toBeLessThanOrEqual(after - 24 * 3600 * 1000 + 100);
    expect(limit).toBe(100);
    expect(pg.capturedSql).toContain('FROM agent_audit_log');
    expect(pg.capturedSql).toContain('ORDER BY id DESC');
  });

  it('account_id + key_id + event_type filters compose', async () => {
    const pg = new FakePg();
    const handler = rbAuditTail();
    await handler.run(
      {
        ...baseInput,
        options: {
          since: '2026-04-29T00:00:00Z',
          account_id: '11111111-2222-3333-4444-555555555555',
          key_id: 'agk_x',
          event_type: 'revoke',
          limit: 50,
        },
      },
      makeDeps(pg),
    );
    expect(pg.capturedParams).toHaveLength(5);
    expect((pg.capturedParams[0] as Date).toISOString()).toBe('2026-04-29T00:00:00.000Z');
    expect(pg.capturedParams[1]).toBe('11111111-2222-3333-4444-555555555555');
    expect(pg.capturedParams[2]).toBe('agk_x');
    expect(pg.capturedParams[3]).toBe('revoke');
    expect(pg.capturedParams[4]).toBe(50);
    expect(pg.capturedSql).toContain('account_id = $2::uuid');
    expect(pg.capturedSql).toContain('key_id = $3');
    expect(pg.capturedSql).toContain('event_type = $4');
  });

  it('hard-caps limit at 10_000 to prevent DoS', async () => {
    const pg = new FakePg();
    const handler = rbAuditTail();
    await handler.run({ ...baseInput, options: { limit: 1_000_000 } }, makeDeps(pg));
    const limit = pg.capturedParams[pg.capturedParams.length - 1] as number;
    expect(limit).toBe(10_000);
  });

  it('floors limit at 1 (rejects 0 / negative)', async () => {
    const pg = new FakePg();
    const handler = rbAuditTail();
    await handler.run({ ...baseInput, options: { limit: -5 } }, makeDeps(pg));
    expect(pg.capturedParams[pg.capturedParams.length - 1]).toBe(1);
    await handler.run({ ...baseInput, options: { limit: 0 } }, makeDeps(pg));
    expect(pg.capturedParams[pg.capturedParams.length - 1]).toBe(1);
  });

  it('returns rows + count from the underlying query', async () => {
    const pg = new FakePg();
    pg.rows = [
      { id: '1', event_type: 'revoke' },
      { id: '2', event_type: 'rotate' },
    ];
    const handler = rbAuditTail();
    const out = (await handler.run({ ...baseInput, options: {} }, makeDeps(pg))) as {
      rows: unknown[];
      count: number;
    };
    expect(out.rows).toHaveLength(2);
    expect(out.count).toBe(2);
  });
});
