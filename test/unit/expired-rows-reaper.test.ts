/**
 * Unit: reapExpiredRows (SPEC §3.14 + §5.1.1).
 *
 * Mocks pg.query to verify the SQL shape (cutoff, terminal-state
 * guard on idempotency) and the rowCount return values.
 */
import { describe, it, expect } from 'vitest';
import { reapExpiredRows } from '../../src/jobs/expired-rows-reaper.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface QueryLog {
  text: string;
  params?: ReadonlyArray<unknown>;
}

class FakePg {
  log: QueryLog[] = [];
  apprRowCount = 0;
  idemRowCount = 0;
  async query<R>(text: string, params?: ReadonlyArray<unknown>) {
    this.log.push(params !== undefined ? { text, params } : { text });
    if (/agent_recovery_approvals/.test(text)) {
      return { rows: [] as unknown as R[], rowCount: this.apprRowCount };
    }
    if (/agent_idempotency/.test(text)) {
      return { rows: [] as unknown as R[], rowCount: this.idemRowCount };
    }
    return { rows: [] as unknown as R[], rowCount: 0 };
  }
}

describe('reapExpiredRows (SPEC §3.14 + §5.1.1)', () => {
  it('issues two DELETEs with cutoff = now - grace_ms', async () => {
    const pg = new FakePg();
    const fixed = new Date('2027-06-15T12:00:00Z');
    await reapExpiredRows({
      postgres: pg as unknown as PostgresAdapter,
      now: () => fixed,
    });
    expect(pg.log).toHaveLength(2);
    const a = pg.log[0]!;
    const i = pg.log[1]!;
    expect(a.text).toMatch(/DELETE FROM agent_recovery_approvals/);
    expect(a.params?.[0]).toBeInstanceOf(Date);
    expect((a.params?.[0] as Date).getTime()).toBe(
      fixed.getTime() - 60 * 60 * 1000,
    );
    expect(i.text).toMatch(/DELETE FROM agent_idempotency/);
    expect(i.text).toMatch(
      /state IN \('completed', 'failed', 'manual_required'\)/,
    );
  });

  it('returns the rowCount from each DELETE', async () => {
    const pg = new FakePg();
    pg.apprRowCount = 7;
    pg.idemRowCount = 13;
    const out = await reapExpiredRows({
      postgres: pg as unknown as PostgresAdapter,
    });
    expect(out.recovery_approvals_deleted).toBe(7);
    expect(out.idempotency_deleted).toBe(13);
  });

  it('honors a custom grace_ms', async () => {
    const pg = new FakePg();
    const fixed = new Date('2027-06-15T12:00:00Z');
    await reapExpiredRows({
      postgres: pg as unknown as PostgresAdapter,
      now: () => fixed,
      grace_ms: 5000,
    });
    const cutoff = pg.log[0]!.params?.[0] as Date;
    expect(cutoff.getTime()).toBe(fixed.getTime() - 5000);
  });

  it('idempotency DELETE only targets terminal states (preserves pending/unknown for the §5.1.2 reconciler)', async () => {
    const pg = new FakePg();
    await reapExpiredRows({ postgres: pg as unknown as PostgresAdapter });
    const idem = pg.log[1]!;
    expect(idem.text).not.toMatch(/state IN \('pending'/);
    expect(idem.text).toMatch(/'completed'/);
    expect(idem.text).toMatch(/'failed'/);
    expect(idem.text).toMatch(/'manual_required'/);
  });
});
