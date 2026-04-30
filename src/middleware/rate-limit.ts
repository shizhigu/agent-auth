/**
 * Multi-dimensional rate-limit helper. SPEC §5.2.2.
 *
 * The lib does not own the HTTP layer, so this is a *helper* that route
 * adapters call before doing real work:
 *
 *   const decision = await checkRateLimits(redis, [
 *     dim('per_key', `rl:k:${key_id}`, 100, 60),
 *     dim('per_account', `rl:a:${account_id}`, 5000, 86400),
 *     dim('per_ip', `rl:ip:${ip_hash_hex}`, 5, 3600),
 *   ]);
 *   if (!decision.allowed) throw gcraReject(decision);
 *
 * The order of `dimensions` is the order of evaluation; any reject
 * short-circuits. Per §5.2.2 footer: cluster mode evaluates each
 * dimension atomically per-key but checks across keys are not atomic
 * (acceptable for rate limiting; not a correctness issue).
 */

import { gcraEvaluate, gcraReject } from '../reliability/gcra.js';
import type { GcraDecision, GcraDimension } from '../reliability/gcra.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import { AgentAuthError } from '../errors.js';

export type { GcraDecision, GcraDimension };

/** Convenience: build a GcraDimension. */
export function dim(
  dimension: string,
  key: string,
  burst: number,
  period_seconds: number,
  cost_units?: number,
): GcraDimension {
  return cost_units !== undefined
    ? { dimension, key, burst, period_seconds, cost_units }
    : { dimension, key, burst, period_seconds };
}

/** Evaluate dimensions; throws AgentAuthError(429) on reject. */
export async function enforceRateLimits(
  redis: RedisAdapter,
  dimensions: ReadonlyArray<GcraDimension>,
  now_ms = 0,
): Promise<GcraDecision> {
  const decision = await gcraEvaluate(redis, dimensions, now_ms);
  if (!decision.allowed) {
    throw gcraReject(decision);
  }
  return decision;
}

/** Re-export so callers don't have to import from two modules. */
export { gcraReject };
export type { AgentAuthError };
