/**
 * Cache invalidation pipeline. SPEC §5.3.4 / §5.3.5.
 *
 * Postgres is authoritative — Redis cache must follow it. After any Tier B
 * mutation that changes a key's auth-relevant state, the lib must:
 *   1. DEL the per-key cache entry, so the next validation reads Postgres
 *      (or epoch-mismatches the local LRU).
 *   2. PUBLISH to `agent-auth:invalidate:key:<key_id>` so peer processes
 *      drop their local LRU entry within their pubsub latency.
 *   3. SREM from `agent-auth:account-keys:<account_id>` so account-wide
 *      invalidation walks the right set.
 *
 * Errors during step 1-3 are warnings, NOT correctness gates: the epoch
 * bump (revocation-epoch) is the authoritative knob. A Redis outage means
 * cached entries remain valid until their cached_epoch goes stale, which
 * happens within ~30 s as the epoch propagates.
 */

import {
  KEY_PREFIX_KEY,
  KEY_PREFIX_ACCOUNT_KEYS,
  PUBSUB_INVALIDATE_KEY_PREFIX,
  PUBSUB_INVALIDATE_ACCOUNT_PREFIX,
  type RedisAdapter,
} from '../storage/redis-adapter.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

/**
 * Invalidate a single key in cache. Best-effort: any Redis error is
 * swallowed (logged by caller). Postgres is the authority.
 */
export async function invalidateKey(
  redis: RedisAdapter,
  key_id: string,
  account_id?: string,
): Promise<void> {
  try {
    await redis.del(KEY_PREFIX_KEY + key_id);
  } catch {
    /* swallow */
  }
  try {
    await redis.publish(PUBSUB_INVALIDATE_KEY_PREFIX + key_id, '1');
  } catch {
    /* swallow */
  }
  if (account_id) {
    try {
      await redis.srem(KEY_PREFIX_ACCOUNT_KEYS + account_id, key_id);
    } catch {
      /* swallow */
    }
  }
}

/**
 * Invalidate every active/rotating key for an account. Postgres is consulted
 * for the authoritative list (Redis SET is acceleration only; missing
 * entries would be dangerous, stale entries are harmless per §5.3.5).
 */
export async function invalidateAccountKeys(
  pg: PostgresAdapter,
  redis: RedisAdapter,
  account_id: string,
): Promise<{ invalidated: ReadonlyArray<string> }> {
  const res = await pg.query<{ key_id: string }>(
    `SELECT key_id FROM agent_api_keys
      WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
    [account_id],
  );
  const ids = res.rows.map((r) => r.key_id);
  for (const kid of ids) {
    // Per-key invalidation already best-effort.
    await invalidateKey(redis, kid, account_id);
  }
  // Publish an account-wide invalidation channel for SaaS-side hooks.
  try {
    await redis.publish(PUBSUB_INVALIDATE_ACCOUNT_PREFIX + account_id, '1');
  } catch {
    /* swallow */
  }
  return { invalidated: ids };
}
