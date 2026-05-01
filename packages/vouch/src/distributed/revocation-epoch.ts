/**
 * Revocation epoch maintenance. SPEC §5.3.2.
 *
 * Postgres holds the authoritative monotonically-increasing epoch in
 * `agent_revocation_epoch` (singleton). The 0003 trigger enforces strict
 * monotonicity. Whenever a Tier B mutation flips a key/identity/account to
 * a non-active state, we bump the epoch IN THE SAME TRANSACTION, then push
 * the new value to Redis via the Lua MAX script (epoch_max). Redis cannot
 * decrement (Lua MAX guarantee).
 *
 * Validation reads (`validateKey`) consult the Redis copy as the
 * "current" epoch and treat any cache entry whose `cached_epoch` differs
 * as stale (RT-26). Postgres remains authoritative on a Redis miss.
 */

import type { PoolClient } from 'pg';
import type { RedisAdapter } from '../storage/redis-adapter.js';

export interface BumpEpochResult {
  /** New epoch value committed to Postgres. */
  readonly epoch: number;
  /** Value Redis settled on after the Lua MAX (always ≥ Postgres bump). */
  readonly redis_epoch: number;
}

/**
 * Bump the Postgres epoch (must be inside a Tier B transaction) and push
 * the new value to Redis. The Postgres trigger refuses non-strictly-
 * increasing updates so this is safe to call concurrently from many
 * mutators.
 */
export async function bumpEpochInTx(
  client: PoolClient,
  redis: RedisAdapter,
): Promise<BumpEpochResult> {
  const res = await client.query<{ epoch: string }>(
    `UPDATE agent_revocation_epoch
        SET epoch = epoch + 1
      WHERE id = 1
      RETURNING epoch::text AS epoch`,
  );
  const row = res.rows[0];
  if (!row) throw new Error('epoch_singleton_missing');
  const epoch = Number(row.epoch);
  if (!Number.isFinite(epoch)) {
    throw new Error(`epoch_non_numeric: ${row.epoch}`);
  }
  // Push to Redis. proposeEpoch is monotonic; if Redis has already advanced
  // past us (e.g. due to a concurrent commit on another node + replication),
  // the Redis value is correct.
  const redis_epoch = await redis.proposeEpoch(epoch);
  return { epoch, redis_epoch };
}
