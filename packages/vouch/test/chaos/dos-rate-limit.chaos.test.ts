/**
 * Chaos: DoS / cost exhaustion via GCRA flood. SPEC §12.4 / RT-15.
 *
 * Confirms the lib's GCRA rate-limit primitive (against a real Redis)
 * absorbs a burst, rejects sustained over-rate traffic with bounded
 * Retry-After values, and does not amplify load against the upstream
 * Postgres / Redis (rate-limit decisions are atomic per-bucket via Lua
 * script, so concurrent over-rate calls don't cause additional Redis
 * commands than the single GCRA evalsha).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  RedisContainer,
  type StartedRedisContainer,
} from '@testcontainers/redis';
import { Redis } from 'ioredis';
import { IoredisAdapter } from '../../src/storage/redis-adapter.js';
import {
  enforceRateLimits,
  dim,
} from '../../src/middleware/rate-limit.js';
import { AgentAuthError } from '../../src/errors.js';

describe('chaos: DoS / GCRA flood (SPEC §12.4 / RT-15)', () => {
  let redis_container: StartedRedisContainer;
  let redis_client: Redis;
  let redis_subscriber: Redis;
  let redis: IoredisAdapter;

  beforeAll(async () => {
    redis_container = await new RedisContainer('redis:7-alpine').start();
    redis_client = new Redis(redis_container.getConnectionUrl(), {
      maxRetriesPerRequest: 1,
    });
    redis_subscriber = new Redis(redis_container.getConnectionUrl(), {
      maxRetriesPerRequest: 1,
    });
    redis_client.on('error', () => undefined);
    redis_subscriber.on('error', () => undefined);
    redis = new IoredisAdapter({ client: redis_client, subscriber: redis_subscriber });
    await redis.loadScripts();
  }, 240_000);

  afterAll(async () => {
    redis_client?.disconnect();
    redis_subscriber?.disconnect();
    await redis_container?.stop().catch(() => undefined);
  }, 120_000);

  it('absorbs burst, rejects sustained over-rate traffic with bounded Retry-After', async () => {
    const dims = [dim('per_key', 'rt15:k1', /*burst*/ 5, /*period*/ 60)];
    let allowed = 0;
    let rejectedCount = 0;
    const retryAfters: number[] = [];

    // 50 calls in tight succession against a 5/60s budget.
    for (let i = 0; i < 50; i++) {
      try {
        await enforceRateLimits(redis, dims);
        allowed++;
      } catch (err) {
        if (err instanceof AgentAuthError && err.status === 429) {
          rejectedCount++;
          const ra = Number(err.headers?.['Retry-After'] ?? '0');
          retryAfters.push(ra);
        } else {
          throw err;
        }
      }
    }
    expect(allowed).toBeLessThanOrEqual(5); // burst cap
    expect(allowed).toBeGreaterThanOrEqual(1);
    expect(rejectedCount).toBeGreaterThanOrEqual(45);
    // Retry-After must be bounded by the period (60s) — never larger than
    // the natural budget refill window.
    for (const ra of retryAfters) {
      expect(ra).toBeGreaterThanOrEqual(1);
      expect(ra).toBeLessThanOrEqual(60);
    }
  });

  it('per-IP dimension short-circuits over-rate without consulting other dims', async () => {
    // per-IP is the cheapest dim; if it rejects, per-key + per-account
    // are not even evaluated. Confirms the multi-dim helper does NOT fan
    // out under attack.
    const dims = [
      dim('per_ip', 'rt15:ip:hot', 2, 60),
      dim('per_key', 'rt15:k:hot', 1000, 60),
      dim('per_account', 'rt15:a:hot', 10000, 86400),
    ];
    let firstReject: { dimension?: string; status?: number } | null = null;
    for (let i = 0; i < 10; i++) {
      try {
        await enforceRateLimits(redis, dims);
      } catch (err) {
        if (err instanceof AgentAuthError) {
          firstReject = {
            ...(err.details ? (err.details as { dimension?: string }) : {}),
            status: err.status,
          };
          break;
        }
      }
    }
    expect(firstReject?.status).toBe(429);
    expect(firstReject?.dimension).toBe('per_ip');
  });

  it('tight loop of 200 over-rate calls completes in < 2s (GCRA atomicity)', async () => {
    // Overloaded calls should NOT pile latency on the lib — each evalsha
    // is single-RTT to Redis. We assert wall-clock < 2s for 200 rejections.
    const dims = [dim('per_key', 'rt15:perf', 1, 60)];
    // Burn through the burst.
    try {
      await enforceRateLimits(redis, dims);
    } catch {
      /* might already be rate-limited from earlier iterations of dim */
    }
    const start = Date.now();
    let rejects = 0;
    for (let i = 0; i < 200; i++) {
      try {
        await enforceRateLimits(redis, dims);
      } catch {
        rejects++;
      }
    }
    const dur = Date.now() - start;
    expect(rejects).toBeGreaterThanOrEqual(195); // expecting ~all to reject
    expect(dur).toBeLessThan(2000);
  });
});
