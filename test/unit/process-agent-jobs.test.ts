/**
 * Unit: agent_jobs worker (SPEC §3.15).
 *
 * Mocks the postgres adapter + redis adapter to verify the worker:
 *   - claims pending jobs via SELECT FOR UPDATE SKIP LOCKED
 *   - dispatches cache_invalidate_keys → invalidateKey for each key_id
 *   - marks completed on success
 *   - reschedules on transient failure (attempts < max_attempts)
 *   - dead-letters when attempts >= max_attempts
 *   - skips unknown kinds without looping forever
 */
import { describe, it, expect } from 'vitest';
import { processAgentJobs, type JobHandler } from '../../src/jobs/process-agent-jobs.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { RedisAdapter } from '../../src/storage/redis-adapter.js';

interface FakeJobRow {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
  attempts: number;
  max_attempts: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'dead';
  last_error: string | null;
  locked_by: string | null;
}

class FakePg {
  rows: FakeJobRow[] = [];

  async transaction<T>(fn: (client: this) => Promise<T>): Promise<T> {
    return fn(this);
  }

  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    if (/SELECT id::text AS id, kind, payload, attempts, max_attempts/.test(text)) {
      const next = this.rows.find((r) => r.status === 'pending');
      if (!next) return { rows: [] as unknown as R[], rowCount: 0 };
      return { rows: [next] as unknown as R[], rowCount: 1 };
    }
    if (/SET status = 'running'/.test(text)) {
      const id = String(params[0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) {
        r.status = 'running';
        r.locked_by = String(params[1]);
      }
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    if (/SET status = 'completed'/.test(text)) {
      const id = String(params[0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) r.status = 'completed';
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    if (/SET status = 'pending'.*attempts = \$2/s.test(text)) {
      const id = String(params[0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) {
        r.status = 'pending';
        r.attempts = params[1] as number;
        r.last_error = (params[2] as string) ?? null;
        r.locked_by = null;
      }
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    if (/SET status = 'dead'.*attempts = \$2/s.test(text)) {
      const id = String(params[0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) {
        r.status = 'dead';
        r.attempts = params[1] as number;
        r.last_error = (params[2] as string) ?? null;
      }
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    return { rows: [] as unknown as R[], rowCount: 0 };
  }
}

class FakeRedis {
  readonly invalidations: string[] = [];
  readonly published: Array<{ channel: string; message: string }> = [];
  async del(key: string): Promise<number> {
    this.invalidations.push(key);
    return 1;
  }
  async publish(channel: string, message: string): Promise<number> {
    this.published.push({ channel, message });
    return 0;
  }
  async srem(): Promise<number> {
    return 0;
  }
}

describe('processAgentJobs (SPEC §3.15)', () => {
  it('cache_invalidate_keys: iterates key_ids and calls invalidateKey for each', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    pg.rows.push({
      id: '1',
      kind: 'cache_invalidate_keys',
      payload: { key_ids: ['agk_aaa', 'agk_bbb'], reason: 'tier_change', new_tier: 'warm' },
      attempts: 0,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    const out = await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
    });
    expect(out.inspected).toBe(1);
    expect(out.completed).toBe(1);
    expect(out.failed).toBe(0);
    expect(out.dead).toBe(0);
    expect(pg.rows[0]!.status).toBe('completed');
    // invalidateKey calls del on the per-key cache entry for each key_id.
    expect(redis.invalidations.length).toBeGreaterThanOrEqual(2);
  });

  it('reschedules on failure when attempts < max_attempts', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    pg.rows.push({
      id: '2',
      kind: 'broken',
      payload: {},
      attempts: 0,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    const broken: JobHandler = async () => {
      throw new Error('downstream-error');
    };
    const out = await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
      extra_handlers: { broken },
      batch_size: 1,
    });
    expect(out.failed).toBe(1);
    expect(out.dead).toBe(0);
    expect(pg.rows[0]!.status).toBe('pending');
    expect(pg.rows[0]!.attempts).toBe(1);
    expect(pg.rows[0]!.last_error).toBe('downstream-error');
  });

  it('dead-letters when attempts reaches max_attempts', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    pg.rows.push({
      id: '3',
      kind: 'broken',
      payload: {},
      attempts: 4,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const out = await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
      extra_handlers: { broken: async () => { throw new Error('still-broken'); } },
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(out.dead).toBe(1);
    expect(pg.rows[0]!.status).toBe('dead');
    expect(pg.rows[0]!.attempts).toBe(5);
    expect(alerts).toContainEqual({
      label: 'agent_jobs_dead_lettered',
      meta: { id: '3', kind: 'broken', attempts: 5 },
    });
  });

  it('unknown kind: marks completed (no-op) and emits an alert', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    pg.rows.push({
      id: '4',
      kind: 'totally_made_up',
      payload: {},
      attempts: 0,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    const alerts: Array<string> = [];
    const out = await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
      onAlert: (label) => alerts.push(label),
    });
    expect(out.completed).toBe(1);
    expect(pg.rows[0]!.status).toBe('completed');
    expect(alerts).toContain('agent_jobs_unknown_kind');
  });

  it('processes nothing when queue is empty', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    const out = await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
    });
    expect(out.inspected).toBe(0);
  });

  it('claim SQL includes lease-expiry branch so dead-worker rows get reclaimed', async () => {
    // The FakePg returns the first pending row regardless of WHERE
    // clause, so this test asserts the SQL TEXT contains the
    // `status = 'running' AND locked_at < now() - lease` branch
    // (which is the regression-prevention shape — the lease handling
    // itself is exercised end-to-end against real Postgres).
    const pg = new FakePg();
    const redis = new FakeRedis();
    const captured: string[] = [];
    // Override query to capture the SELECT text.
    const origQuery = pg.query.bind(pg);
    pg.query = (async (text: string, params?: ReadonlyArray<unknown>) => {
      captured.push(text);
      return origQuery(text, params);
    }) as typeof pg.query;
    pg.rows.push({
      id: '99',
      kind: 'cache_invalidate_keys',
      payload: { key_ids: [] },
      attempts: 0,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
      lease_timeout_ms: 60_000,
    });
    const select = captured.find((s) => /SELECT id::text/.test(s));
    expect(select).toBeDefined();
    expect(select!).toMatch(/status = 'pending'/);
    expect(select!).toMatch(/status = 'running' AND locked_at <[^$]*now\(\)/);
  });

  it('cache_invalidate_keys ignores non-string / non-agk_ entries (defensive)', async () => {
    const pg = new FakePg();
    const redis = new FakeRedis();
    pg.rows.push({
      id: '5',
      kind: 'cache_invalidate_keys',
      payload: { key_ids: ['agk_ok', 42, 'evil_prefix', null] },
      attempts: 0,
      max_attempts: 5,
      status: 'pending',
      last_error: null,
      locked_by: null,
    });
    await processAgentJobs({
      postgres: pg as unknown as PostgresAdapter,
      redis: redis as unknown as RedisAdapter,
    });
    expect(pg.rows[0]!.status).toBe('completed');
    // Only the well-formed agk_-prefixed entry was forwarded.
    expect(redis.invalidations.some((k) => k.includes('agk_ok'))).toBe(true);
    expect(redis.invalidations.some((k) => k.includes('evil_prefix'))).toBe(false);
  });
});
