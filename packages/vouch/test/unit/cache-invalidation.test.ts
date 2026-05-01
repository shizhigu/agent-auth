import { describe, it, expect } from 'vitest';
import {
  invalidateKey,
  invalidateAccountKeys,
} from '../../src/distributed/cache-invalidation.js';
import {
  InMemoryRedisAdapter,
  KEY_PREFIX_KEY,
  KEY_PREFIX_ACCOUNT_KEYS,
  PUBSUB_INVALIDATE_KEY_PREFIX,
} from '../../src/storage/redis-adapter.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

class FakePg {
  rowsByAccount = new Map<string, string[]>();
  async query<R>(_text: string, params: ReadonlyArray<unknown> = []) {
    const account_id = params[0] as string;
    const ids = this.rowsByAccount.get(account_id) ?? [];
    const rows = ids.map((key_id) => ({ key_id })) as unknown as R[];
    return { rows, rowCount: ids.length };
  }
  async queryOne<R>(): Promise<R | null> {
    return null;
  }
}

describe('invalidateKey (SPEC §5.3.4)', () => {
  it('DELs the key and PUBLISHes invalidation', async () => {
    const redis = new InMemoryRedisAdapter();
    await redis.set(KEY_PREFIX_KEY + 'agk_x', '{"cached":"yes"}');
    let pubMsg: { ch: string; msg: string } | null = null;
    await redis.subscribePattern(PUBSUB_INVALIDATE_KEY_PREFIX + '*', (ch, msg) => {
      pubMsg = { ch, msg };
    });
    await invalidateKey(redis, 'agk_x');
    expect(await redis.get(KEY_PREFIX_KEY + 'agk_x')).toBeNull();
    expect(pubMsg).toEqual({
      ch: PUBSUB_INVALIDATE_KEY_PREFIX + 'agk_x',
      msg: '1',
    });
  });

  it('SREMs the per-account key set when account_id is supplied', async () => {
    const redis = new InMemoryRedisAdapter();
    await redis.sadd(KEY_PREFIX_ACCOUNT_KEYS + 'acc-1', 'agk_x', 'agk_y');
    await invalidateKey(redis, 'agk_x', 'acc-1');
    expect(new Set(await redis.smembers(KEY_PREFIX_ACCOUNT_KEYS + 'acc-1'))).toEqual(
      new Set(['agk_y']),
    );
  });

  it('does not throw when Redis call fails (best-effort cache)', async () => {
    const broken = {
      del: async () => {
        throw new Error('redis-down');
      },
      publish: async () => 0,
      srem: async () => 0,
    };
    await expect(
      invalidateKey(broken as unknown as InMemoryRedisAdapter, 'agk_x'),
    ).resolves.toBeUndefined();
  });
});

describe('invalidateAccountKeys (SPEC §5.3.5)', () => {
  it('reads authoritative list from Postgres and walks each key', async () => {
    const redis = new InMemoryRedisAdapter();
    const pg = new FakePg();
    pg.rowsByAccount.set('acc-1', ['agk_a', 'agk_b']);
    await redis.set(KEY_PREFIX_KEY + 'agk_a', '{}');
    await redis.set(KEY_PREFIX_KEY + 'agk_b', '{}');
    await redis.sadd(KEY_PREFIX_ACCOUNT_KEYS + 'acc-1', 'agk_a', 'agk_b', 'agk_c');

    const out = await invalidateAccountKeys(pg as unknown as PostgresAdapter, redis, 'acc-1');
    expect(new Set(out.invalidated)).toEqual(new Set(['agk_a', 'agk_b']));
    expect(await redis.get(KEY_PREFIX_KEY + 'agk_a')).toBeNull();
    expect(await redis.get(KEY_PREFIX_KEY + 'agk_b')).toBeNull();
    // agk_c was stale in Redis SET but not in DB; we don't add anything new,
    // and the invalidator removed agk_a/agk_b only. Stale entries are
    // harmless per §5.3.5.
    expect(new Set(await redis.smembers(KEY_PREFIX_ACCOUNT_KEYS + 'acc-1'))).toEqual(
      new Set(['agk_c']),
    );
  });
});
