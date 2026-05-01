/**
 * Unit: GET /healthz (SPEC §10.2).
 *
 *   - 200 healthy: barrier readable + redis epoch readable + no open breakers
 *   - 503 with 'redis_unreachable' when redis throws
 *   - 503 with 'postgres_unreachable' when postgres throws
 *   - 503 with 'circuit_breaker_open:<name>' when a registered breaker is open
 *   - 503 reasons aggregate when multiple subsystems fail
 */
import { describe, it, expect } from 'vitest';
import { healthz } from '../../src/routes/healthz.js';
import { CircuitBreaker } from '../../src/reliability/circuit-breaker.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { RedisAdapter } from '../../src/storage/redis-adapter.js';

function pgOk(): PostgresAdapter {
  return {
    async queryOne() {
      return { last_lsn: '16/B374D848', timeline_id: 1 };
    },
  } as unknown as PostgresAdapter;
}
function pgFail(): PostgresAdapter {
  return {
    async queryOne() {
      throw new Error('connect_timeout');
    },
  } as unknown as PostgresAdapter;
}
function redisOk(): RedisAdapter {
  return { async getAuthoritativeEpoch() { return 1; } } as unknown as RedisAdapter;
}
function redisFail(): RedisAdapter {
  return {
    async getAuthoritativeEpoch() {
      throw new Error('econnrefused');
    },
  } as unknown as RedisAdapter;
}

describe('healthz (SPEC §10.2)', () => {
  it('200 healthy when both stores reachable, no breakers', async () => {
    const out = await healthz({ postgres: pgOk(), redis: redisOk(), version: '0.1.0' });
    expect(out.http_status).toBe(200);
    if (out.http_status !== 200) return;
    expect(out.body.status).toBe('healthy');
    expect(out.body.version).toBe('0.1.0');
    expect(out.body.timeline_id).toBe(1);
    expect(out.body.barrier_lsn).toBe('16/B374D848');
    expect(out.body.redis_quorum_acks).toBe(1);
    expect(out.body.circuit_breakers).toEqual({});
  });

  it('503 with redis_unreachable when redis throws', async () => {
    const out = await healthz({ postgres: pgOk(), redis: redisFail() });
    expect(out.http_status).toBe(503);
    if (out.http_status !== 503) return;
    expect(out.body.reasons).toContain('redis_unreachable');
  });

  it('503 with postgres_unreachable when postgres throws', async () => {
    const out = await healthz({ postgres: pgFail(), redis: redisOk() });
    expect(out.http_status).toBe(503);
    if (out.http_status !== 503) return;
    expect(out.body.reasons).toContain('postgres_unreachable');
  });

  it('503 surfaces circuit_breaker_open with the dep name', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1, halfOpenAfter: 999_999 });
    // force open with one failure.
    await cb.execute(() => Promise.reject(new Error('boom'))).catch(() => undefined);
    expect(cb.state_()).toBe('open');
    const out = await healthz({
      postgres: pgOk(),
      redis: redisOk(),
      circuit_breakers: { github_app: cb },
    });
    expect(out.http_status).toBe(503);
    if (out.http_status !== 503) return;
    expect(out.body.reasons).toContain('circuit_breaker_open:github_app');
  });

  it('reasons aggregate when multiple subsystems fail', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1, halfOpenAfter: 999_999 });
    await cb.execute(() => Promise.reject(new Error('boom'))).catch(() => undefined);
    const out = await healthz({
      postgres: pgFail(),
      redis: redisFail(),
      circuit_breakers: { github_app: cb },
    });
    expect(out.http_status).toBe(503);
    if (out.http_status !== 503) return;
    expect(out.body.reasons).toEqual(
      expect.arrayContaining([
        'postgres_unreachable',
        'redis_unreachable',
        'circuit_breaker_open:github_app',
      ]),
    );
  });
});
