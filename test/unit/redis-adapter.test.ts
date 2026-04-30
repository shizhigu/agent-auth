import { describe, it, expect } from 'vitest';
import {
  InMemoryRedisAdapter,
  KEY_REVOCATION_EPOCH,
} from '../../src/storage/redis-adapter.js';

describe('InMemoryRedisAdapter — basic kv', () => {
  it('round-trips GET/SET', async () => {
    const r = new InMemoryRedisAdapter();
    await r.set('a', 'hello');
    expect(await r.get('a')).toBe('hello');
  });

  it('TTL expires GET correctly', async () => {
    let now = 1000;
    const r = new InMemoryRedisAdapter({ now: () => now });
    await r.set('k', 'v', { ex_seconds: 1 });
    expect(await r.get('k')).toBe('v');
    now = 1000 + 1500;
    expect(await r.get('k')).toBeNull();
  });

  it('DEL returns count of removed keys', async () => {
    const r = new InMemoryRedisAdapter();
    await r.set('a', '1');
    await r.set('b', '2');
    expect(await r.del('a', 'b', 'c')).toBe(2);
  });
});

describe('InMemoryRedisAdapter — set ops', () => {
  it('SADD/SMEMBERS/SREM', async () => {
    const r = new InMemoryRedisAdapter();
    expect(await r.sadd('keys:1', 'a', 'b', 'c')).toBe(3);
    expect(new Set(await r.smembers('keys:1'))).toEqual(new Set(['a', 'b', 'c']));
    expect(await r.srem('keys:1', 'a', 'd')).toBe(1);
    expect(new Set(await r.smembers('keys:1'))).toEqual(new Set(['b', 'c']));
  });
});

describe('InMemoryRedisAdapter — pubsub', () => {
  it('publishes to pattern subscribers', async () => {
    const r = new InMemoryRedisAdapter();
    const got: Array<{ ch: string; msg: string }> = [];
    await r.subscribePattern('agent-auth:invalidate:key:*', (ch, msg) =>
      got.push({ ch, msg }),
    );
    const n = await r.publish('agent-auth:invalidate:key:agk_xyz', '1');
    expect(n).toBe(1);
    expect(got).toEqual([{ ch: 'agent-auth:invalidate:key:agk_xyz', msg: '1' }]);
  });

  it('does not match unrelated channels', async () => {
    const r = new InMemoryRedisAdapter();
    let calls = 0;
    await r.subscribePattern('agent-auth:invalidate:account:*', () => calls++);
    await r.publish('agent-auth:invalidate:key:agk_x', '1');
    expect(calls).toBe(0);
  });
});

describe('InMemoryRedisAdapter — epoch (Lua MAX, SPEC §5.3.2)', () => {
  it('initial epoch is 0', async () => {
    const r = new InMemoryRedisAdapter();
    expect(await r.getAuthoritativeEpoch()).toBe(0);
  });

  it('proposeEpoch advances when proposed > current', async () => {
    const r = new InMemoryRedisAdapter();
    expect(await r.proposeEpoch(5)).toBe(5);
    expect(await r.getAuthoritativeEpoch()).toBe(5);
  });

  it('proposeEpoch is monotonic — earlier value cannot decrement', async () => {
    const r = new InMemoryRedisAdapter();
    await r.proposeEpoch(10);
    expect(await r.proposeEpoch(7)).toBe(10);
    expect(await r.getAuthoritativeEpoch()).toBe(10);
  });

  it('returns numeric value via direct GET KEY_REVOCATION_EPOCH', async () => {
    const r = new InMemoryRedisAdapter();
    await r.proposeEpoch(42);
    expect(await r.get(KEY_REVOCATION_EPOCH)).toBe('42');
  });
});
