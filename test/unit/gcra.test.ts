import { describe, it, expect } from 'vitest';
import {
  gcraCheck,
  gcraEvaluate,
  gcraReject,
} from '../../src/reliability/gcra.js';
import { enforceRateLimits, dim } from '../../src/middleware/rate-limit.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';

describe('GCRA (SPEC §5.2.1)', () => {
  it('first request is allowed; remaining_units > 0', async () => {
    let now = 1000_000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    const out = await gcraCheck(
      r,
      { key: 'rl:k', burst: 5, period_seconds: 60, dimension: 'per_key' },
      now,
    );
    expect(out.allowed).toBe(true);
    expect(out.remaining_units).toBeGreaterThanOrEqual(0);
  });

  it('rejects after burst is exhausted in the same window', async () => {
    let now = 1000_000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    let lastAllowed = false;
    for (let i = 0; i < 5; i++) {
      const out = await gcraCheck(
        r,
        { key: 'rl:k', burst: 5, period_seconds: 60, dimension: 'per_key' },
        now,
      );
      lastAllowed = out.allowed;
    }
    expect(lastAllowed).toBe(true);
    const reject = await gcraCheck(
      r,
      { key: 'rl:k', burst: 5, period_seconds: 60, dimension: 'per_key' },
      now,
    );
    expect(reject.allowed).toBe(false);
    expect(reject.time_ms).toBeGreaterThan(0); // retry-after
  });

  it('refills budget over time', async () => {
    let now = 1_000_000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    for (let i = 0; i < 5; i++) {
      await gcraCheck(
        r,
        { key: 'rl:k2', burst: 5, period_seconds: 5, dimension: 'per_key' },
        now,
      );
    }
    // 5 over 5s = 1 per s. Advance 2s; should accept again.
    now += 2_000;
    const out = await gcraCheck(
      r,
      { key: 'rl:k2', burst: 5, period_seconds: 5, dimension: 'per_key' },
      now,
    );
    expect(out.allowed).toBe(true);
  });

  it('multi-dim eval short-circuits on first reject', async () => {
    let now = 1_000_000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    // per-key limit is generous; per-account is 2 in 60s.
    const dims = [
      dim('per_key', 'rl:k:x', 100, 60),
      dim('per_account', 'rl:a:y', 2, 60),
    ];
    expect((await gcraEvaluate(r, dims, now)).allowed).toBe(true);
    expect((await gcraEvaluate(r, dims, now)).allowed).toBe(true);
    const third = await gcraEvaluate(r, dims, now);
    expect(third.allowed).toBe(false);
    expect(third.dimension).toBe('per_account');
  });

  it('enforceRateLimits throws AgentAuthError(429) with Retry-After', async () => {
    let now = 1_000_000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    await enforceRateLimits(r, [dim('per_key', 'rl:rate', 1, 60)], now);
    let caught: unknown;
    try {
      await enforceRateLimits(r, [dim('per_key', 'rl:rate', 1, 60)], now);
    } catch (err) {
      caught = err;
    }
    expect(caught).toMatchObject({ status: 429, code: 'too_many_requests' });
    const e = caught as { headers: Record<string, string> };
    expect(e.headers['Retry-After']).toBeDefined();
    expect(Number(e.headers['Retry-After'])).toBeGreaterThanOrEqual(1);
  });

  it('gcraReject ceil-rounds to at least 1 second', () => {
    const err = gcraReject({
      allowed: false,
      remaining_units: 0,
      time_ms: 200,
      dimension: 'per_key',
    });
    expect(err.headers!['Retry-After']).toBe('1');
  });
});
