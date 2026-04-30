/**
 * GCRA rate-limit helper. SPEC §5.2.1.
 *
 * Wraps the `gcra` Lua script (registered on the Redis adapter) with a
 * typed result. Each rate-check returns whether the request is allowed,
 * the remaining budget, and either retry_after_ms (on reject) or
 * reset_after_ms (on accept).
 *
 * The Lua script is atomic per-bucket — concurrent rate-checks against
 * the same key cannot race past the limit. Multi-dimensional limits
 * (per-key + per-account + per-route + per-ip) walk dimensions in order;
 * any rejection short-circuits.
 */

import { AgentAuthError } from '../errors.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';

export interface GcraDimension {
  /** Stable bucket key, e.g. `ratelimit:per_key:agk_xxx`. */
  readonly key: string;
  readonly burst: number;
  readonly period_seconds: number;
  readonly cost_units?: number; // default 1
  /** Surfaced on the metric label so SaaSes can graph by dimension. */
  readonly dimension: string;
}

export interface GcraDecision {
  readonly allowed: boolean;
  readonly remaining_units: number;
  /** Accept: ms until budget fully replenishes. Reject: ms until cost is allowed. */
  readonly time_ms: number;
  readonly dimension: string;
}

/**
 * Run the GCRA Lua script for one dimension. Returns a typed decision.
 * `now_ms` is optional — if 0/omitted the script uses Redis TIME, which
 * is correct for production. Tests pass a fixed clock.
 */
export async function gcraCheck(
  redis: RedisAdapter,
  dim: GcraDimension,
  now_ms = 0,
): Promise<GcraDecision> {
  const args = [
    String(dim.period_seconds),
    String(dim.burst),
    String(dim.cost_units ?? 1),
    String(now_ms),
  ];
  const out = await redis.evalSha('gcra', [dim.key], args);
  const [allowed, remaining, time_ms] = decodeTuple(out);
  return {
    allowed: allowed === 1,
    remaining_units: remaining,
    time_ms,
    dimension: dim.dimension,
  };
}

function decodeTuple(out: unknown): [number, number, number] {
  // ioredis returns a JS array directly; in-memory adapter encodes as JSON
  // so it can pass through the same string|number|null evalSha return type.
  if (Array.isArray(out)) {
    return [Number(out[0]), Number(out[1]), Number(out[2])];
  }
  if (typeof out === 'string') {
    try {
      const parsed = JSON.parse(out) as unknown;
      if (Array.isArray(parsed)) {
        return [Number(parsed[0]), Number(parsed[1]), Number(parsed[2])];
      }
    } catch {
      /* fallthrough */
    }
  }
  throw new Error('gcra_unexpected_result');
}

/**
 * Walk dimensions and return the first reject (or final accept). On reject,
 * the caller surfaces 429 too_many_requests with `Retry-After` set to
 * `Math.ceil(time_ms / 1000)`.
 */
export async function gcraEvaluate(
  redis: RedisAdapter,
  dimensions: ReadonlyArray<GcraDimension>,
  now_ms = 0,
): Promise<GcraDecision> {
  let last: GcraDecision | null = null;
  for (const dim of dimensions) {
    const decision = await gcraCheck(redis, dim, now_ms);
    if (!decision.allowed) return decision;
    last = decision;
  }
  if (!last) throw new Error('gcra_no_dimensions');
  return last;
}

/**
 * Convenience: convert a reject decision into AgentAuthError(429). Caller
 * can throw the result directly.
 */
export function gcraReject(decision: GcraDecision): AgentAuthError {
  const retryAfter = Math.max(1, Math.ceil(decision.time_ms / 1000));
  return new AgentAuthError(429, 'too_many_requests', undefined, {
    headers: { 'Retry-After': String(retryAfter) },
    details: { dimension: decision.dimension, retry_after_ms: decision.time_ms },
  });
}
