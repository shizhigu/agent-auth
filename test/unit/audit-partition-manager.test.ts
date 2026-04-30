/**
 * Unit: daily audit-log partition manager. SPEC §3.8 / §13.1.2.
 *
 * Mocks PostgresAdapter to verify:
 *   - lookahead_days drives the loop count
 *   - partition names are deterministic (YYYY_MM_DD)
 *   - already-existing partitions are skipped
 *   - bound expressions reject unsafe partition names
 */
import { describe, it, expect } from 'vitest';
import { manageAuditPartitions } from '../../src/jobs/audit-partition-manager.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface QueryLog {
  text: string;
  params: ReadonlyArray<unknown> | undefined;
}

class FakePg {
  log: QueryLog[] = [];
  /** Names that already exist (returned as non-null by to_regclass). */
  existing = new Set<string>();
  async queryOne<R>(text: string, params?: ReadonlyArray<unknown>): Promise<R | null> {
    this.log.push({ text, params });
    if (/to_regclass/.test(text)) {
      const name = (params?.[0] as string) ?? '';
      const regclass = this.existing.has(name) ? name : null;
      return { regclass } as unknown as R;
    }
    return null;
  }
  async query(text: string, params?: ReadonlyArray<unknown>) {
    this.log.push({ text, params });
    return { rows: [], rowCount: 0 };
  }
}

describe('manageAuditPartitions (SPEC §3.8 / §13.1.2)', () => {
  it('creates lookahead_days partitions with YYYY_MM_DD names', async () => {
    const pg = new FakePg();
    const out = await manageAuditPartitions({
      postgres: pg as unknown as PostgresAdapter,
      lookahead_days: 5,
      now: () => new Date('2026-12-30T12:00:00Z'),
    });
    expect(out.created).toEqual([
      'agent_audit_log_2026_12_30',
      'agent_audit_log_2026_12_31',
      'agent_audit_log_2027_01_01',
      'agent_audit_log_2027_01_02',
      'agent_audit_log_2027_01_03',
    ]);
    expect(out.skipped).toEqual([]);
    // Each create issues two queries: existence check + CREATE.
    expect(pg.log.filter((q) => /to_regclass/.test(q.text))).toHaveLength(5);
    expect(pg.log.filter((q) => /CREATE TABLE/.test(q.text))).toHaveLength(5);
  });

  it('skips already-existing partitions; only missing ones are created', async () => {
    const pg = new FakePg();
    pg.existing.add('agent_audit_log_2027_06_15');
    pg.existing.add('agent_audit_log_2027_06_17');
    const out = await manageAuditPartitions({
      postgres: pg as unknown as PostgresAdapter,
      lookahead_days: 3,
      now: () => new Date('2027-06-15T00:00:00Z'),
    });
    expect(out.created).toEqual(['agent_audit_log_2027_06_16']);
    expect([...out.skipped].sort()).toEqual([
      'agent_audit_log_2027_06_15',
      'agent_audit_log_2027_06_17',
    ]);
  });

  it('rejects out-of-range lookahead_days', async () => {
    const pg = new FakePg();
    await expect(
      manageAuditPartitions({
        postgres: pg as unknown as PostgresAdapter,
        lookahead_days: 0,
      }),
    ).rejects.toThrow('lookahead_days');
    await expect(
      manageAuditPartitions({
        postgres: pg as unknown as PostgresAdapter,
        lookahead_days: 91,
      }),
    ).rejects.toThrow('lookahead_days');
  });

  it('emits onAlert for each created partition', async () => {
    const pg = new FakePg();
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    await manageAuditPartitions({
      postgres: pg as unknown as PostgresAdapter,
      lookahead_days: 2,
      now: () => new Date('2027-01-01T00:00:00Z'),
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(alerts).toHaveLength(2);
    expect(alerts.every((a) => a.label === 'audit_partition_created')).toBe(true);
    expect(alerts[0]!.meta).toMatchObject({
      name: 'agent_audit_log_2027_01_01',
      from: '2027-01-01 00:00:00+00',
      to: '2027-01-02 00:00:00+00',
    });
  });
});
