import { describe, it, expect } from 'vitest';
import {
  makeBarrierCheck,
  RouteToPrimaryError,
  lsnCompare,
} from '../../src/distributed/multi-region-barrier.js';
import { ServiceUnavailableError } from '../../src/errors.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface FakeState {
  is_primary: boolean;
  timeline_id: number;
  replay_lsn: string;
  authoritative_last_lsn: string;
  authoritative_timeline_id: number;
}

function makePgs(state: FakeState): { primary: PostgresAdapter; local: PostgresAdapter } {
  const primary = {
    async queryOne(text: string) {
      if (/last_lsn::text AS last_lsn, timeline_id/.test(text)) {
        return {
          last_lsn: state.authoritative_last_lsn,
          timeline_id: state.authoritative_timeline_id,
        };
      }
      return null;
    },
  } as unknown as PostgresAdapter;
  const local = {
    async queryOne(text: string) {
      if (/pg_is_in_recovery/.test(text)) return { ir: !state.is_primary };
      if (/pg_control_checkpoint/.test(text)) return { timeline_id: state.timeline_id };
      if (/pg_last_wal_replay_lsn/.test(text)) return { lsn: state.replay_lsn };
      return null;
    },
  } as unknown as PostgresAdapter;
  return { primary, local };
}

describe('makeBarrierCheck (SPEC §4.4.2-4)', () => {
  it('no-op when local is the primary (not in recovery)', async () => {
    const pgs = makePgs({
      is_primary: true,
      timeline_id: 1,
      replay_lsn: '0/100',
      authoritative_last_lsn: '0/200',
      authoritative_timeline_id: 1,
    });
    const check = makeBarrierCheck({ ...pgs, on_lag: 'fail_closed' });
    await expect(check()).resolves.toBeUndefined();
  });

  it('rejects 503 failover_in_progress when timeline mismatch', async () => {
    const pgs = makePgs({
      is_primary: false,
      timeline_id: 1,
      replay_lsn: '0/100',
      authoritative_last_lsn: '0/100',
      authoritative_timeline_id: 2,
    });
    const check = makeBarrierCheck({ ...pgs, on_lag: 'fail_closed' });
    await expect(check()).rejects.toThrowError(
      expect.objectContaining({ status: 503, code: 'failover_in_progress' }),
    );
  });

  it('rejects 503 region_replication_stale when local is behind barrier (fail_closed)', async () => {
    const pgs = makePgs({
      is_primary: false,
      timeline_id: 1,
      replay_lsn: '0/AB',
      authoritative_last_lsn: '0/FF',
      authoritative_timeline_id: 1,
    });
    const check = makeBarrierCheck({ ...pgs, on_lag: 'fail_closed' });
    await expect(check()).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('throws RouteToPrimaryError when on_lag=route_to_primary and lagged', async () => {
    const pgs = makePgs({
      is_primary: false,
      timeline_id: 1,
      replay_lsn: '0/AB',
      authoritative_last_lsn: '0/FF',
      authoritative_timeline_id: 1,
    });
    const check = makeBarrierCheck({ ...pgs, on_lag: 'route_to_primary' });
    await expect(check()).rejects.toBeInstanceOf(RouteToPrimaryError);
  });

  it('passes when local replay catches up to barrier', async () => {
    const pgs = makePgs({
      is_primary: false,
      timeline_id: 1,
      replay_lsn: '0/FF',
      authoritative_last_lsn: '0/FF',
      authoritative_timeline_id: 1,
    });
    const check = makeBarrierCheck({ ...pgs, on_lag: 'fail_closed' });
    await expect(check()).resolves.toBeUndefined();
  });
});

describe('lsnCompare', () => {
  it('compares pg_lsn strings as 64-bit values', () => {
    expect(lsnCompare('0/0', '0/1')).toBe(-1);
    expect(lsnCompare('1/0', '0/FFFFFFFF')).toBe(1);
    expect(lsnCompare('A/B', 'A/B')).toBe(0);
    expect(lsnCompare('FF/FF', 'FF/FE')).toBe(1);
  });

  it('throws on malformed LSN', () => {
    expect(() => lsnCompare('not-an-lsn', '0/0')).toThrow();
  });
});
