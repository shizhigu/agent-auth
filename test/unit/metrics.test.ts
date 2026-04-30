import { describe, it, expect } from 'vitest';
import { MetricsRegistry } from '../../src/observability/metrics.js';

describe('MetricsRegistry (SPEC §7.1)', () => {
  it('counter inc + exposition format', () => {
    const reg = new MetricsRegistry('test_prefix');
    const c = reg.counter('hits_total', 'requests', ['outcome']);
    c.inc({ outcome: 'ok' });
    c.inc({ outcome: 'ok' });
    c.inc({ outcome: 'fail' });
    const text = reg.exposition();
    expect(text).toContain('# TYPE test_prefix_hits_total counter');
    expect(text).toContain('test_prefix_hits_total{outcome="ok"} 2');
    expect(text).toContain('test_prefix_hits_total{outcome="fail"} 1');
  });

  it('gauge set/inc + exposition', () => {
    const reg = new MetricsRegistry();
    const g = reg.gauge('queue_depth', 'jobs in queue');
    g.set({}, 5);
    g.inc({}, 2);
    const text = reg.exposition();
    expect(text).toContain('agent_auth_queue_depth 7');
    expect(text).toContain('# TYPE agent_auth_queue_depth gauge');
  });

  it('histogram observe + bucket counts', () => {
    const reg = new MetricsRegistry();
    const h = reg.histogram(
      'op_seconds',
      'op latency',
      ['op'],
      [0.001, 0.01, 0.1, 1],
    );
    h.observe({ op: 'x' }, 0.0005);
    h.observe({ op: 'x' }, 0.05);
    h.observe({ op: 'x' }, 0.5);
    const text = reg.exposition();
    expect(text).toMatch(/agent_auth_op_seconds_bucket\{op="x",le="0.001"\} 1/);
    expect(text).toMatch(/agent_auth_op_seconds_bucket\{op="x",le="0.01"\} 1/);
    expect(text).toMatch(/agent_auth_op_seconds_bucket\{op="x",le="0.1"\} 2/);
    expect(text).toMatch(/agent_auth_op_seconds_bucket\{op="x",le="1"\} 3/);
    expect(text).toMatch(/agent_auth_op_seconds_bucket\{op="x",le="\+Inf"\} 3/);
    expect(text).toMatch(/agent_auth_op_seconds_count\{op="x"\} 3/);
  });

  it('refuses kind mismatch on re-registration', () => {
    const reg = new MetricsRegistry();
    reg.counter('m', 'help');
    expect(() => reg.gauge('m', 'help')).toThrow(/metric_kind_mismatch/);
  });

  it('label values are scrubbed before exposition (RT-44)', () => {
    const reg = new MetricsRegistry();
    const c = reg.counter('reqs', 'help', ['who']);
    c.inc({ who: 'agk_xxxx1234.' + 'a'.repeat(43) });
    const text = reg.exposition();
    expect(text).toContain('[REDACTED:PATTERN]');
    expect(text).not.toMatch(/agk_xxxx/);
  });
});
