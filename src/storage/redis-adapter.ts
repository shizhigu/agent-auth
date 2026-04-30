/**
 * Redis adapter — wraps ioredis with the operations agent-auth needs:
 *   - GET / SET / DEL with TTL (cache layer §5.3.1)
 *   - PUBLISH / SUBSCRIBE for cross-process invalidation §5.3.4
 *   - Lua script registration (epoch MAX §5.3.2; GCRA §5.2.1 added in M5)
 *   - Authoritative epoch read (`agent-auth:revocation-epoch`) §5.3.3
 *
 * Postgres is the authoritative store; Redis is acceleration only. Every
 * Redis-driven decision must have a Postgres fallback (RT-3, RT-25).
 *
 * Two impls live here:
 *   - IoredisAdapter: wraps an ioredis client (production path)
 *   - InMemoryRedisAdapter: deterministic test impl
 *
 * Both implement RedisAdapter so callers swap by config.
 */

import type { Redis } from 'ioredis';

export const KEY_REVOCATION_EPOCH = 'agent-auth:revocation-epoch';
export const KEY_PREFIX_KEY = 'agent-auth:key:';
export const KEY_PREFIX_ACCOUNT_KEYS = 'agent-auth:account-keys:';
export const PUBSUB_INVALIDATE_KEY_PREFIX = 'agent-auth:invalidate:key:';
export const PUBSUB_INVALIDATE_ACCOUNT_PREFIX = 'agent-auth:invalidate:account:';

/**
 * Lua script — epoch MAX. Argv[1] = proposed epoch (string).
 * Sets KEYS[1] := max(current, proposed); returns the value after.
 * Monotonicity guarantee per §5.3.2: concurrent revoke writers can never
 * decrement the cached epoch even if they reach Redis out of order.
 */
export const LUA_EPOCH_MAX = `
local key = KEYS[1]
local proposed = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', key) or '0')
if proposed > current then
  redis.call('SET', key, tostring(proposed))
  return proposed
end
return current
`;

export interface RedisAdapter {
  /** GET <key> — returns null on miss. */
  get(key: string): Promise<string | null>;
  /** SET <key> <value> [EX <ttl_seconds>]. */
  set(
    key: string,
    value: string,
    opts?: { ex_seconds?: number },
  ): Promise<void>;
  /** DEL <key1> [<key2> ...]. Returns count actually removed. */
  del(...keys: string[]): Promise<number>;
  /** SADD <set> <member1> [<member2> ...]. */
  sadd(set: string, ...members: string[]): Promise<number>;
  /** SMEMBERS <set>. */
  smembers(set: string): Promise<string[]>;
  /** SREM <set> <member1> [<member2> ...]. */
  srem(set: string, ...members: string[]): Promise<number>;
  /** PUBLISH <channel> <message>. Returns number of subscribers reached. */
  publish(channel: string, message: string): Promise<number>;
  /** Run a registered Lua script (looked up by name). */
  evalSha(scriptName: string, keys: string[], args: string[]): Promise<string | number | null>;
  /** Subscribe to channel patterns. Callback receives (channel, message). */
  subscribePattern(
    pattern: string,
    cb: (channel: string, message: string) => void,
  ): Promise<void>;
  /** Authoritative epoch read (uncached). Returns 0 if Redis is empty. */
  getAuthoritativeEpoch(): Promise<number>;
  /** Atomically set epoch := max(current, proposed) and return the new value. */
  proposeEpoch(proposed: number): Promise<number>;
  /** Drain & shut down. Optional in tests. */
  close?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// IoredisAdapter
// ---------------------------------------------------------------------------

export interface IoredisAdapterConfig {
  /** Already-constructed ioredis client (mode-aware: standalone, sentinel, cluster). */
  readonly client: Redis;
  /** Separate ioredis client for SUBSCRIBE — required because subscribed clients
   *  cannot run regular commands. */
  readonly subscriber: Redis;
}

export class IoredisAdapter implements RedisAdapter {
  private readonly scriptShas = new Map<string, string>();

  constructor(private readonly cfg: IoredisAdapterConfig) {}

  /** Load Lua scripts and cache their SHAs. Call before serving traffic. */
  async loadScripts(): Promise<void> {
    const sha = await this.cfg.client.script('LOAD', LUA_EPOCH_MAX);
    if (typeof sha !== 'string') {
      throw new Error('redis_script_load_returned_non_string');
    }
    this.scriptShas.set('epoch_max', sha);
  }

  async get(key: string): Promise<string | null> {
    return this.cfg.client.get(key);
  }

  async set(
    key: string,
    value: string,
    opts?: { ex_seconds?: number },
  ): Promise<void> {
    if (opts?.ex_seconds !== undefined) {
      await this.cfg.client.set(key, value, 'EX', opts.ex_seconds);
    } else {
      await this.cfg.client.set(key, value);
    }
  }

  async del(...keys: string[]): Promise<number> {
    if (keys.length === 0) return 0;
    return this.cfg.client.del(...keys);
  }

  async sadd(set: string, ...members: string[]): Promise<number> {
    if (members.length === 0) return 0;
    return this.cfg.client.sadd(set, ...members);
  }

  async smembers(set: string): Promise<string[]> {
    return this.cfg.client.smembers(set);
  }

  async srem(set: string, ...members: string[]): Promise<number> {
    if (members.length === 0) return 0;
    return this.cfg.client.srem(set, ...members);
  }

  async publish(channel: string, message: string): Promise<number> {
    return this.cfg.client.publish(channel, message);
  }

  async evalSha(
    scriptName: string,
    keys: string[],
    args: string[],
  ): Promise<string | number | null> {
    const sha = this.scriptShas.get(scriptName);
    if (!sha) throw new Error(`redis_script_not_loaded: ${scriptName}`);
    try {
      const out = await this.cfg.client.evalsha(sha, keys.length, ...keys, ...args);
      return out as string | number | null;
    } catch (err) {
      // Re-load + retry on NOSCRIPT (e.g. after Redis flush).
      if (err instanceof Error && /NOSCRIPT/.test(err.message)) {
        await this.loadScripts();
        const reloaded = this.scriptShas.get(scriptName);
        if (!reloaded) throw err;
        const out = await this.cfg.client.evalsha(
          reloaded,
          keys.length,
          ...keys,
          ...args,
        );
        return out as string | number | null;
      }
      throw err;
    }
  }

  async subscribePattern(
    pattern: string,
    cb: (channel: string, message: string) => void,
  ): Promise<void> {
    await this.cfg.subscriber.psubscribe(pattern);
    this.cfg.subscriber.on('pmessage', (_pattern, channel, message) => {
      cb(channel, message);
    });
  }

  async getAuthoritativeEpoch(): Promise<number> {
    const v = await this.cfg.client.get(KEY_REVOCATION_EPOCH);
    if (v === null) return 0;
    const n = Number(v);
    if (!Number.isFinite(n)) {
      throw new Error(`redis_epoch_non_numeric: ${v}`);
    }
    return n;
  }

  async proposeEpoch(proposed: number): Promise<number> {
    const out = await this.evalSha('epoch_max', [KEY_REVOCATION_EPOCH], [String(proposed)]);
    if (typeof out === 'number') return out;
    if (typeof out === 'string') return Number(out);
    throw new Error(`epoch_max_returned_unexpected: ${String(out)}`);
  }

  async close(): Promise<void> {
    await Promise.allSettled([this.cfg.client.quit(), this.cfg.subscriber.quit()]);
  }
}

// ---------------------------------------------------------------------------
// InMemoryRedisAdapter
// ---------------------------------------------------------------------------

interface InMemEntry {
  value: string;
  expires_at?: number; // ms epoch
}

/**
 * In-memory adapter for unit + integration tests. Simulates the subset of
 * Redis semantics the lib uses (TTL expiry, sets, pubsub, atomic Lua MAX).
 * Does NOT simulate cluster slots, AOF replay, or eviction policy.
 */
export class InMemoryRedisAdapter implements RedisAdapter {
  private kv = new Map<string, InMemEntry>();
  private sets = new Map<string, Set<string>>();
  private subscribers: Array<{
    pattern: RegExp;
    cb: (channel: string, message: string) => void;
  }> = [];
  private now: () => number;

  constructor(opts?: { now?: () => number }) {
    this.now = opts?.now ?? Date.now;
  }

  private check(key: string): InMemEntry | null {
    const e = this.kv.get(key);
    if (!e) return null;
    if (e.expires_at !== undefined && this.now() >= e.expires_at) {
      this.kv.delete(key);
      return null;
    }
    return e;
  }

  async get(key: string): Promise<string | null> {
    return this.check(key)?.value ?? null;
  }

  async set(
    key: string,
    value: string,
    opts?: { ex_seconds?: number },
  ): Promise<void> {
    const entry: InMemEntry = { value };
    if (opts?.ex_seconds !== undefined) {
      entry.expires_at = this.now() + opts.ex_seconds * 1000;
    }
    this.kv.set(key, entry);
  }

  async del(...keys: string[]): Promise<number> {
    let n = 0;
    for (const k of keys) if (this.kv.delete(k)) n++;
    return n;
  }

  async sadd(set: string, ...members: string[]): Promise<number> {
    let s = this.sets.get(set);
    if (!s) {
      s = new Set();
      this.sets.set(set, s);
    }
    let added = 0;
    for (const m of members) {
      if (!s.has(m)) {
        s.add(m);
        added++;
      }
    }
    return added;
  }

  async smembers(set: string): Promise<string[]> {
    return Array.from(this.sets.get(set) ?? []);
  }

  async srem(set: string, ...members: string[]): Promise<number> {
    const s = this.sets.get(set);
    if (!s) return 0;
    let n = 0;
    for (const m of members) if (s.delete(m)) n++;
    return n;
  }

  async publish(channel: string, message: string): Promise<number> {
    let count = 0;
    for (const sub of this.subscribers) {
      if (sub.pattern.test(channel)) {
        sub.cb(channel, message);
        count++;
      }
    }
    return count;
  }

  async evalSha(
    scriptName: string,
    keys: string[],
    args: string[],
  ): Promise<string | number | null> {
    if (scriptName === 'epoch_max') {
      const k = keys[0];
      const proposed = Number(args[0] ?? '0');
      if (!k || !Number.isFinite(proposed)) {
        throw new Error('epoch_max_invalid_args');
      }
      const cur = Number(this.check(k)?.value ?? '0');
      const next = proposed > cur ? proposed : cur;
      this.kv.set(k, { value: String(next) });
      return next;
    }
    throw new Error(`unknown_script: ${scriptName}`);
  }

  async subscribePattern(
    pattern: string,
    cb: (channel: string, message: string) => void,
  ): Promise<void> {
    // Convert Redis glob to regex: * -> .*
    const escaped = pattern.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&').replace(/\*/g, '.*');
    this.subscribers.push({ pattern: new RegExp(`^${escaped}$`), cb });
  }

  async getAuthoritativeEpoch(): Promise<number> {
    return Number(this.check(KEY_REVOCATION_EPOCH)?.value ?? '0');
  }

  async proposeEpoch(proposed: number): Promise<number> {
    const out = await this.evalSha(
      'epoch_max',
      [KEY_REVOCATION_EPOCH],
      [String(proposed)],
    );
    return Number(out);
  }

  async close(): Promise<void> {
    this.kv.clear();
    this.sets.clear();
    this.subscribers = [];
  }

  /** Test-only: forcibly expire a key. */
  forceExpire(key: string): void {
    this.kv.delete(key);
  }
}
