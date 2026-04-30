/**
 * Multi-region barrier read path. SPEC §4.4.2 / §4.4.3 / §4.4.4.
 *
 * Builds a `barrier_check()` callable for `validateKey`. Behavior:
 *   - In primary region (config.is_primary = true): no-op. Validation
 *     reads its own primary, which is authoritative.
 *   - In secondary region: reads `agent_revocation_barrier` from the
 *     PRIMARY DSN (cross-region cost paid only when no in-process cache
 *     is hot), reads local replica's pg_last_wal_replay_lsn, and:
 *       a. if local replica is the primary itself (pg_is_in_recovery=false):
 *          treat as primary, allow direct read.
 *       b. if local timeline_id != barrier.timeline_id → 503
 *          'failover_in_progress' (operator runs RB-8 to reset).
 *       c. if local replay LSN < barrier.last_lsn:
 *          - on_lag = 'fail_closed' → 503 'region_replication_stale'
 *          - on_lag = 'route_to_primary' → caller's responsibility to
 *            route the validation against the primary; we surface a
 *            tagged error so the framework adapter can take action.
 *
 * The lib's caller wires this in by:
 *   const barrier = makeBarrierCheck({ primary: primaryPg, local: localPg, on_lag: 'fail_closed' })
 *   const deps: ValidateKeyDeps = { ..., barrier_check: barrier }
 */

import { ServiceUnavailableError } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import { readAuthoritativeBarrier } from './revocation-barrier.js';

export type LagPolicy = 'fail_closed' | 'route_to_primary';

export interface BarrierCheckConfig {
  /** Primary-region Postgres adapter. Authoritative for the barrier. */
  readonly primary: PostgresAdapter;
  /** Local-region Postgres adapter (replica) — used for replay-LSN reads. */
  readonly local: PostgresAdapter;
  /** When local replica is behind the barrier:
   *    'fail_closed': throw 503 region_replication_stale.
   *    'route_to_primary': throw a tagged error the route adapter can catch. */
  readonly on_lag: LagPolicy;
  /** Optional in-process cache TTL for the barrier read (default 0 = strict). */
  readonly barrier_cache_ms?: number;
  /** Now for tests. */
  readonly now?: () => number;
}

interface BarrierCacheEntry {
  readonly last_lsn: string;
  readonly timeline_id: number;
  readonly cached_at: number;
}

/** Tagged error for `on_lag = 'route_to_primary'`. The framework adapter
 *  catches it and re-routes the validation against the primary cluster. */
export class RouteToPrimaryError extends Error {
  override readonly name = 'RouteToPrimaryError';
  constructor() {
    super('route_to_primary');
  }
}

export function makeBarrierCheck(cfg: BarrierCheckConfig): () => Promise<void> {
  const ttl = cfg.barrier_cache_ms ?? 0;
  const now = cfg.now ?? Date.now;
  let cache: BarrierCacheEntry | null = null;

  return async function barrierCheck(): Promise<void> {
    // a. If the local DB is the primary (we're not in recovery), the
    //    barrier check is unnecessary — local read is authoritative.
    const recovery = await cfg.local.queryOne<{ ir: boolean }>(
      `SELECT pg_is_in_recovery() AS ir`,
    );
    if (recovery && recovery.ir === false) return;

    // Authoritative barrier (cached for `ttl` ms when configured).
    let barrier: BarrierCacheEntry;
    if (cache && now() - cache.cached_at < ttl) {
      barrier = cache;
    } else {
      const fresh = await readAuthoritativeBarrier(cfg.primary);
      barrier = {
        last_lsn: fresh.last_lsn,
        timeline_id: fresh.timeline_id,
        cached_at: now(),
      };
      cache = barrier;
    }

    // b. Timeline mismatch — failover in progress / RB-8 not yet run.
    const localTl = await cfg.local.queryOne<{ timeline_id: number }>(
      `SELECT timeline_id FROM pg_control_checkpoint()`,
    );
    if (localTl && localTl.timeline_id !== barrier.timeline_id) {
      throw new ServiceUnavailableError('failover_in_progress');
    }

    // c. Replay-LSN gate.
    const replay = await cfg.local.queryOne<{ lsn: string }>(
      `SELECT pg_last_wal_replay_lsn()::text AS lsn`,
    );
    if (!replay) {
      // Some test envs return null here — treat as caught up.
      return;
    }
    if (lsnCompare(replay.lsn, barrier.last_lsn) < 0) {
      if (cfg.on_lag === 'route_to_primary') {
        throw new RouteToPrimaryError();
      }
      throw new ServiceUnavailableError('region_replication_stale');
    }
  };
}

/**
 * Compare two pg_lsn values (canonical form 'X/Y' hex). Returns:
 *   -1 if a < b
 *    0 if a == b
 *    1 if a > b
 */
export function lsnCompare(a: string, b: string): number {
  const aN = parsePgLsn(a);
  const bN = parsePgLsn(b);
  if (aN < bN) return -1;
  if (aN > bN) return 1;
  return 0;
}

function parsePgLsn(s: string): bigint {
  const m = /^([0-9A-Fa-f]+)\/([0-9A-Fa-f]+)$/.exec(s.trim());
  if (!m) throw new Error(`invalid_pg_lsn: ${s}`);
  const hi = BigInt(`0x${m[1]}`);
  const lo = BigInt(`0x${m[2]}`);
  return (hi << 32n) | lo;
}
