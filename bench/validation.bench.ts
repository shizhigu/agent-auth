/**
 * Validation hot-path benchmarks. SPEC §12.6.
 *
 * Targets:
 *   validation_cache_hit_same_az:   P50 < 5ms,  P99 < 50ms
 *   validation_cache_miss_with_hmac: P50 < 30ms, P99 < 100ms
 *
 * The local-cache path is the bench focus — Redis + Postgres branches
 * are exercised in integration tests with real containers.
 */

import { bench, describe, beforeAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { LocalCache } from '../src/cache/local-cache.js';
import { InMemoryKmsAdapter } from '../src/storage/kms-adapter.js';
import { InMemoryRedisAdapter } from '../src/storage/redis-adapter.js';
import { hmacWithPepper } from '../src/crypto/hmac-pepper.js';
import { validateKey } from '../src/middleware/validate-key.js';
import type { PostgresAdapter } from '../src/storage/postgres-adapter.js';
import type { KeyCache } from '../src/types.js';

class FakePg {
  rows: Map<string, Record<string, unknown>> = new Map();
  async queryOne<R>(_t: string, params: ReadonlyArray<unknown>): Promise<R | null> {
    return ((this.rows.get(params[0] as string) ?? null) as unknown) as R | null;
  }
}

interface BenchEntry {
  bearer: string;
  key_id: string;
  cache_entry: KeyCache;
}

const TOTAL_KEYS = 10_000;
const ENTRIES: BenchEntry[] = [];
let kms: InMemoryKmsAdapter;
let redis: InMemoryRedisAdapter;
let pg: FakePg;
let localCache: LocalCache;

beforeAll(async () => {
  kms = new InMemoryKmsAdapter();
  redis = new InMemoryRedisAdapter();
  pg = new FakePg();
  localCache = new LocalCache({ capacity: TOTAL_KEYS, ttl_ms: 60_000 });

  const pepper = await kms.getCurrentPepper();

  for (let i = 0; i < TOTAL_KEYS; i++) {
    const secret = randomBytes(32);
    const public_id = randomBytes(6).toString('base64url');
    const key_id = `agk_${public_id}`;
    const key_hash = hmacWithPepper(pepper.data, secret);
    const account_id = `acc-${i}`;

    pg.rows.set(key_id, {
      key_id,
      account_id,
      account_status: 'active',
      account_tier: 'cold',
      issued_via_identity_id: `id-${i}`,
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: String(i),
      identity_display_handle: `octo-${i}`,
      identity_assurance_level: 'medium',
      key_hash,
      key_pepper_version: 1,
      scopes: ['read'],
      tier: 'cold',
      rotation_state: 'active',
      revoked_at: null,
      rotation_grace_expires_at: null,
      expires_at: null,
    });

    const entry: KeyCache = {
      key_id,
      account_id,
      account_status: 'active',
      issuing_identity_id: `id-${i}`,
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: String(i),
      identity_assurance_level: 'medium',
      key_hash,
      key_pepper_version: 1,
      scopes: Object.freeze(['read']),
      tier: 'cold',
      rotation_state: 'active',
      revoked_at: null,
      grace_expires_at: null,
      expires_at: null,
      cached_epoch: 0,
      cached_at: Date.now(),
      redis_expires_at: Date.now() + 60_000,
    };
    localCache.set(key_id, entry);
    ENTRIES.push({
      bearer: `${key_id}.${secret.toString('base64url')}`,
      key_id,
      cache_entry: entry,
    });
  }
});

const deps = () => ({
  postgres: pg as unknown as PostgresAdapter,
  redis,
  kms,
  localCache,
  redis_cache_ttl_seconds: 30,
});

describe('validation hot path', () => {
  bench(
    'validation_cache_hit_same_az (local cache)',
    async () => {
      const idx = Math.floor(Math.random() * TOTAL_KEYS);
      const entry = ENTRIES[idx]!;
      await validateKey(entry.bearer, deps());
    },
    { iterations: 5_000, time: 2_000 },
  );

  bench(
    'validation_cache_miss_with_hmac (local cleared, falls to Postgres)',
    async () => {
      const idx = Math.floor(Math.random() * TOTAL_KEYS);
      const entry = ENTRIES[idx]!;
      // Drop just this entry from the local cache so the next call
      // exercises the Postgres fallback + HMAC verify.
      localCache.delete(entry.key_id);
      await validateKey(entry.bearer, deps());
    },
    { iterations: 1_000, time: 2_000 },
  );
});
