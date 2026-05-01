/**
 * In-process LRU cache for KeyCache entries. Mirrors SPEC §5.3.1:
 *   - 1000-entry capacity
 *   - 30s TTL (validate-key adds the entry's redis_expires_at; we double-check)
 *   - invalidated on Redis pubsub `agent-auth:invalidate:*`
 *
 * The cache key is the `key_id` (e.g. `agk_abc12345`). The value is the
 * KeyCache snapshot taken at insertion time. The cache is best-effort:
 * a miss always falls through to Redis, which falls through to Postgres.
 *
 * Implementation note: Map preserves insertion order in V8, so we move
 * recently-touched entries to the end (delete + reinsert) to make LRU
 * eviction trivial — drop the oldest entry when over capacity.
 */

import type { KeyCache } from '../types.js';

export interface LocalCacheOptions {
  readonly capacity?: number; // default 1000
  readonly ttl_ms?: number; // hard ceiling regardless of redis_expires_at; default 30s
  readonly now?: () => number; // injectable clock for tests
}

export class LocalCache {
  private readonly map = new Map<string, KeyCache>();
  private readonly capacity: number;
  private readonly ttl_ms: number;
  private readonly now: () => number;

  constructor(opts: LocalCacheOptions = {}) {
    this.capacity = opts.capacity ?? 1000;
    this.ttl_ms = opts.ttl_ms ?? 30_000;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Get an entry. Returns null on miss OR if the entry is past its TTL
   * (in which case it is also evicted as a side effect).
   */
  get(key_id: string): KeyCache | null {
    const entry = this.map.get(key_id);
    if (!entry) return null;
    const t = this.now();
    const expired =
      t >= entry.redis_expires_at || t >= entry.cached_at + this.ttl_ms;
    if (expired) {
      this.map.delete(key_id);
      return null;
    }
    // LRU bump: move to end.
    this.map.delete(key_id);
    this.map.set(key_id, entry);
    return entry;
  }

  set(key_id: string, entry: KeyCache): void {
    if (this.map.has(key_id)) this.map.delete(key_id);
    this.map.set(key_id, entry);
    while (this.map.size > this.capacity) {
      const oldest = this.map.keys().next().value;
      if (oldest === undefined) break;
      this.map.delete(oldest);
    }
  }

  delete(key_id: string): void {
    this.map.delete(key_id);
  }

  clear(): void {
    this.map.clear();
  }

  /** Test introspection. */
  size(): number {
    return this.map.size;
  }

  /** Test introspection: the keys currently in the LRU, in insertion order. */
  keys(): ReadonlyArray<string> {
    return Array.from(this.map.keys());
  }
}
