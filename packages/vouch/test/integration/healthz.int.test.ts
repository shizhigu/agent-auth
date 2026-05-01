/**
 * Integration: GET /healthz (SPEC §10.2) against real Postgres + Redis.
 *
 *   - 200 healthy with timeline_id + barrier_lsn from the live singleton
 *   - 503 with 'redis_unreachable' when Redis is stopped via testcontainers
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { healthz } from '../../src/routes/healthz.js';
import { captureBarrierAfterCommit } from '../../src/distributed/revocation-barrier.js';

describe('integration: healthz (SPEC §10.2)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
    // Force a non-trivial barrier value into the singleton.
    await captureBarrierAfterCommit(fix.postgres);
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('200 healthy: returns SPEC-shaped body with live timeline_id + barrier_lsn', async () => {
    const out = await healthz({
      postgres: fix.postgres,
      redis: fix.redis,
      version: '0.1.0-int',
    });
    expect(out.http_status).toBe(200);
    if (out.http_status !== 200) return;
    expect(out.body.status).toBe('healthy');
    expect(out.body.version).toBe('0.1.0-int');
    // timeline_id is 1 on a freshly-promoted single-region instance,
    // but accept anything ≥ 1 to keep the test robust to test ordering.
    expect(out.body.timeline_id).toBeGreaterThanOrEqual(1);
    // barrier_lsn matches Postgres pg_lsn shape (X/Y hex).
    expect(out.body.barrier_lsn).toMatch(/^[0-9A-F]+\/[0-9A-F]+$/i);
    expect(out.body.redis_quorum_acks).toBe(1);
    expect(out.body.circuit_breakers).toEqual({});
  });

  it('503 unhealthy: Redis stopped → reasons includes redis_unreachable', async () => {
    // Stop Redis via testcontainers; the lib's getAuthoritativeEpoch should fail.
    await fix.redis_container.stop();
    try {
      const out = await healthz({
        postgres: fix.postgres,
        redis: fix.redis,
      });
      expect(out.http_status).toBe(503);
      if (out.http_status !== 503) return;
      expect(out.body.status).toBe('unhealthy');
      expect(out.body.reasons).toContain('redis_unreachable');
    } finally {
      // Don't re-start; the suite's afterAll will clean up.
    }
  });
});
