/**
 * Unit: rotation-grace expirer (SPEC §2.7.3).
 *
 * Mocks the postgres adapter to verify the SQL shape and onAlert payload
 * without requiring a live DB.
 */
import { describe, it, expect } from 'vitest';
import { expireRotationGrace } from '../../src/jobs/rotation-grace-expirer.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface QueryLog {
  text: string;
  params?: ReadonlyArray<unknown>;
}

class FakePg {
  log: QueryLog[] = [];
  rows: Array<{ key_id: string }> = [];
  async query<R>(text: string, params?: ReadonlyArray<unknown>) {
    this.log.push(params !== undefined ? { text, params } : { text });
    return {
      rows: this.rows as unknown as R[],
      rowCount: this.rows.length,
    };
  }
}

describe('expireRotationGrace (SPEC §2.7.3)', () => {
  it('issues an UPDATE with rotation_state=rotated WHERE rotation_state=rotating AND grace past now', async () => {
    const pg = new FakePg();
    const fixed = new Date('2027-06-15T12:00:00Z');
    await expireRotationGrace({
      postgres: pg as unknown as PostgresAdapter,
      now: () => fixed,
    });
    expect(pg.log).toHaveLength(1);
    const q = pg.log[0]!;
    expect(q.text).toContain("SET rotation_state = 'rotated'");
    expect(q.text).toContain("rotation_state = 'rotating'");
    expect(q.text).toContain('rotation_grace_expires_at < $1');
    expect(q.params?.[0]).toBe(fixed);
  });

  it('returns the count of expired rows from the RETURNING projection', async () => {
    const pg = new FakePg();
    pg.rows = [{ key_id: 'agk_a' }, { key_id: 'agk_b' }, { key_id: 'agk_c' }];
    const out = await expireRotationGrace({
      postgres: pg as unknown as PostgresAdapter,
    });
    expect(out.expired).toBe(3);
  });

  it('emits onAlert with first_key_id when batch is non-empty', async () => {
    const pg = new FakePg();
    pg.rows = [{ key_id: 'agk_first' }, { key_id: 'agk_second' }];
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    await expireRotationGrace({
      postgres: pg as unknown as PostgresAdapter,
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.label).toBe('rotation_grace_expired_batch');
    expect(alerts[0]!.meta).toMatchObject({
      count: 2,
      first_key_id: 'agk_first',
    });
  });

  it('does NOT emit onAlert when batch is empty', async () => {
    const pg = new FakePg();
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const out = await expireRotationGrace({
      postgres: pg as unknown as PostgresAdapter,
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(out.expired).toBe(0);
    expect(alerts).toHaveLength(0);
  });
});
