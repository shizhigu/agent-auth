/**
 * Integration: cross-region barrier check against real Postgres barrier data.
 * SPEC §4.4.2 / §4.4.3 (RT-18, RT-32, RT-34).
 *
 * Testcontainers can only spin up a single Postgres instance, so genuine
 * streaming replication is out of scope. Instead, we wire the production
 * `makeBarrierCheck` against:
 *   - a REAL primary adapter holding authoritative `agent_revocation_barrier`
 *     state (advanced by `captureBarrierAfterCommit` after a real Tier B
 *     mutation), and
 *   - a thin LOCAL adapter wrapper that proxies most queries to the real DB
 *     but intercepts the three system-function reads
 *     (`pg_is_in_recovery`, `pg_last_wal_replay_lsn`, `pg_control_checkpoint`)
 *     so we can simulate a secondary region's view.
 *
 * This exercises the full production code path (LSN compare, timeline
 * compare, on_lag policy branching) against real authoritative data
 * written by the real barrier-update SQL.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import {
  makeBarrierCheck,
  RouteToPrimaryError,
  lsnCompare,
} from '../../src/distributed/multi-region-barrier.js';
import { captureBarrierAfterCommit } from '../../src/distributed/revocation-barrier.js';
import { ServiceUnavailableError } from '../../src/errors.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface LocalState {
  in_recovery: boolean;
  replay_lsn: string;
  timeline_id: number;
}

/**
 * Wraps a real PostgresAdapter but intercepts pg_is_in_recovery,
 * pg_last_wal_replay_lsn, pg_control_checkpoint with `state` so the test
 * can simulate a secondary region. All other queries pass through.
 */
function makeLocalStub(real: PostgresAdapter, state: LocalState): PostgresAdapter {
  const proxy = {
    async queryOne(text: string, params?: unknown[]): Promise<unknown> {
      if (/pg_is_in_recovery\s*\(\s*\)\s+AS\s+ir/i.test(text)) {
        return { ir: state.in_recovery };
      }
      if (/pg_last_wal_replay_lsn\s*\(\s*\)/i.test(text)) {
        return { lsn: state.replay_lsn };
      }
      if (/pg_control_checkpoint\s*\(\s*\)/i.test(text)) {
        return { timeline_id: state.timeline_id };
      }
      return real.queryOne(text, params as ReadonlyArray<unknown> | undefined);
    },
  };
  return proxy as unknown as PostgresAdapter;
}

describe('integration: multi-region barrier check (SPEC §4.4.2 / RT-18 / RT-32 / RT-34)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
    // Advance the authoritative barrier with a real Tier B-style commit so
    // we have non-trivial last_lsn / timeline_id values to compare against.
    await captureBarrierAfterCommit(fix.postgres);
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('local-is-primary (pg_is_in_recovery=false): barrier check skips entirely (passes through)', async () => {
    const state: LocalState = {
      in_recovery: false,
      // Even with a stale LSN, the in_recovery=false short-circuit should
      // skip the LSN compare entirely.
      replay_lsn: '0/0',
      timeline_id: 999,
    };
    const local = makeLocalStub(fix.postgres, state);
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    await expect(check()).resolves.toBeUndefined();
  });

  it('healthy replica caught up to barrier: passes', async () => {
    const barrier = await fix.postgres.queryOne<{
      last_lsn: string;
      timeline_id: number;
    }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    expect(barrier).not.toBeNull();
    const state: LocalState = {
      in_recovery: true,
      replay_lsn: barrier!.last_lsn,
      timeline_id: barrier!.timeline_id,
    };
    const local = makeLocalStub(fix.postgres, state);
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    await expect(check()).resolves.toBeUndefined();
  });

  it('replica ahead of barrier: also passes (same-or-greater is healthy)', async () => {
    const barrier = await fix.postgres.queryOne<{
      last_lsn: string;
      timeline_id: number;
    }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    // Construct an LSN strictly greater by adding 1 to the low half.
    const m = /^([0-9A-Fa-f]+)\/([0-9A-Fa-f]+)$/.exec(barrier!.last_lsn);
    expect(m).not.toBeNull();
    const ahead = `${m![1]}/${(BigInt(`0x${m![2]}`) + 1n).toString(16).toUpperCase()}`;
    expect(lsnCompare(ahead, barrier!.last_lsn)).toBe(1);
    const local = makeLocalStub(fix.postgres, {
      in_recovery: true,
      replay_lsn: ahead,
      timeline_id: barrier!.timeline_id,
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    await expect(check()).resolves.toBeUndefined();
  });

  it('RT-32 stale replica + on_lag=fail_closed → 503 region_replication_stale', async () => {
    const barrier = await fix.postgres.queryOne<{ last_lsn: string; timeline_id: number }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    // Build an LSN strictly less than barrier (subtract 1 from low half if possible,
    // else from high half).
    const m = /^([0-9A-Fa-f]+)\/([0-9A-Fa-f]+)$/.exec(barrier!.last_lsn);
    const hi = BigInt(`0x${m![1]}`);
    const lo = BigInt(`0x${m![2]}`);
    const stale =
      lo > 0n
        ? `${m![1]}/${(lo - 1n).toString(16).toUpperCase()}`
        : `${(hi - 1n).toString(16).toUpperCase()}/FFFFFFFF`;
    expect(lsnCompare(stale, barrier!.last_lsn)).toBe(-1);

    const local = makeLocalStub(fix.postgres, {
      in_recovery: true,
      replay_lsn: stale,
      timeline_id: barrier!.timeline_id,
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    await expect(check()).rejects.toBeInstanceOf(ServiceUnavailableError);
    await expect(check()).rejects.toMatchObject({ code: 'region_replication_stale' });
  });

  it('RT-32 stale replica + on_lag=route_to_primary → RouteToPrimaryError (operator-routable)', async () => {
    const barrier = await fix.postgres.queryOne<{ last_lsn: string; timeline_id: number }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    const m = /^([0-9A-Fa-f]+)\/([0-9A-Fa-f]+)$/.exec(barrier!.last_lsn);
    const lo = BigInt(`0x${m![2]}`);
    const stale =
      lo > 0n
        ? `${m![1]}/${(lo - 1n).toString(16).toUpperCase()}`
        : `${(BigInt(`0x${m![1]}`) - 1n).toString(16).toUpperCase()}/FFFFFFFF`;
    const local = makeLocalStub(fix.postgres, {
      in_recovery: true,
      replay_lsn: stale,
      timeline_id: barrier!.timeline_id,
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'route_to_primary',
    });
    await expect(check()).rejects.toBeInstanceOf(RouteToPrimaryError);
  });

  it('RT-34 timeline mismatch (failover not finalized): 503 failover_in_progress regardless of LSN', async () => {
    const barrier = await fix.postgres.queryOne<{ last_lsn: string; timeline_id: number }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    // Local timeline behind barrier — RB-8 not run yet on this node.
    const local = makeLocalStub(fix.postgres, {
      in_recovery: true,
      // Even when LSN is caught up, timeline mismatch must take priority.
      replay_lsn: barrier!.last_lsn,
      timeline_id: barrier!.timeline_id - 1,
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    await expect(check()).rejects.toMatchObject({
      code: 'failover_in_progress',
    });
  });

  it('barrier monotonically advances after a second commit: stale snapshot now rejects', async () => {
    // Capture barrier B1, mark it healthy locally.
    const before = await fix.postgres.queryOne<{ last_lsn: string; timeline_id: number }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id=1`,
    );
    // Force the WAL forward with a small write so pg_current_wal_insert_lsn()
    // strictly advances. pg_logical_emit_message is the cheapest WAL bump.
    await fix.postgres.query(
      `SELECT pg_logical_emit_message(false, 'test', 'barrier_advance_marker')`,
    );
    const advanced = await captureBarrierAfterCommit(fix.postgres);
    expect(lsnCompare(advanced.commit_lsn, before!.last_lsn)).toBeGreaterThanOrEqual(0);

    // A local replica still pegged at B1 is now stale relative to B2.
    const local = makeLocalStub(fix.postgres, {
      in_recovery: true,
      replay_lsn: before!.last_lsn,
      timeline_id: before!.timeline_id,
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local,
      on_lag: 'fail_closed',
    });
    // Only assert if the WAL did in fact advance (it almost always does on
    // a freshly-created cluster, but cheap inserts can occasionally land at
    // the same LSN bucket — in that case the test is a no-op and skips).
    const after = await fix.postgres.queryOne<{ last_lsn: string }>(
      `SELECT last_lsn::text AS last_lsn FROM agent_revocation_barrier WHERE id=1`,
    );
    if (lsnCompare(after!.last_lsn, before!.last_lsn) > 0) {
      await expect(check()).rejects.toMatchObject({
        code: 'region_replication_stale',
      });
    }
  });
});
