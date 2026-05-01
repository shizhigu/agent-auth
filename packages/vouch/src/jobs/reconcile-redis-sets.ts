/**
 * Redis SET drift reconciler. SPEC §5.3.6.
 *
 * Walks every account that's been active in the last 7 days, compares its
 * `agent-auth:account-keys:<account_id>` SET in Redis to the authoritative
 * Postgres list, SADDs missing entries and SREMs stale ones. Cardinality
 * over 1000 emits a metric for ops review.
 */

import {
  KEY_PREFIX_ACCOUNT_KEYS,
  type RedisAdapter,
} from '../storage/redis-adapter.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface ReconcileRedisSetsDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface ReconcileRedisSetsResult {
  readonly inspected: number;
  readonly added: number;
  readonly removed: number;
  readonly oversize: number;
}

interface AccountRow {
  id: string;
}
interface KeyRow {
  key_id: string;
}

export async function reconcileAccountKeySets(
  deps: ReconcileRedisSetsDeps,
): Promise<ReconcileRedisSetsResult> {
  const accounts = await deps.postgres.query<AccountRow>(
    `SELECT id::text AS id FROM agent_accounts
      WHERE status = 'active' AND updated_at > now() - interval '7 days'`,
  );

  let inspected = 0;
  let added = 0;
  let removed = 0;
  let oversize = 0;

  for (const acc of accounts.rows) {
    inspected++;
    const dbKeys = await deps.postgres.query<KeyRow>(
      `SELECT key_id FROM agent_api_keys
        WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
      [acc.id],
    );
    const dbSet = new Set(dbKeys.rows.map((r) => r.key_id));
    const setKey = KEY_PREFIX_ACCOUNT_KEYS + acc.id;
    const redisMembers = await deps.redis.smembers(setKey);
    const redisSet = new Set(redisMembers);
    const missing = [...dbSet].filter((k) => !redisSet.has(k));
    const stale = [...redisSet].filter((k) => !dbSet.has(k));
    if (missing.length > 0) {
      added += await deps.redis.sadd(setKey, ...missing);
    }
    if (stale.length > 0) {
      removed += await deps.redis.srem(setKey, ...stale);
    }
    const card = redisSet.size + missing.length - stale.length;
    if (card > 1000) {
      oversize++;
      deps.onAlert?.('account_key_set_too_large', {
        account_id: acc.id,
        scard: card,
      });
    }
  }
  return { inspected, added, removed, oversize };
}
