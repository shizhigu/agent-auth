import { describe, it, expect, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  validateKey,
  parseApiKey,
  encodeKeyCache,
  decodeKeyCache,
  type ValidateKeyDeps,
} from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type {
  AccountStatus,
  IdentityStatus,
  RotationState,
} from '../../src/types.js';

interface FakeKeyRow {
  key_id: string;
  account_id: string;
  account_status: AccountStatus;
  account_tier: 'cold' | 'warm' | 'hot';
  issued_via_identity_id: string;
  issuing_identity_status: IdentityStatus;
  identity_provider: string;
  identity_subject: string;
  identity_display_handle: string | null;
  identity_assurance_level: 'low' | 'medium' | 'high';
  key_hash: Buffer;
  key_pepper_version: number;
  scopes: string[];
  tier: 'cold' | 'warm' | 'hot';
  rotation_state: RotationState;
  revoked_at: Date | null;
  rotation_grace_expires_at: Date | null;
  expires_at: Date | null;
}

class FakePg {
  rows: Map<string, FakeKeyRow> = new Map();
  callCount = 0;

  async queryOne<R>(_text: string, params: ReadonlyArray<unknown>): Promise<R | null> {
    this.callCount++;
    const id = params[0] as string;
    const r = this.rows.get(id);
    return (r as unknown as R) ?? null;
  }
}

function fakePgAsAdapter(p: FakePg): PostgresAdapter {
  // Only validateKey() uses queryOne; the other methods are unreachable.
  return p as unknown as PostgresAdapter;
}

describe('parseApiKey', () => {
  it('accepts the canonical wire format', () => {
    const parsed = parseApiKey('agk_abc12345.' + 'a'.repeat(43));
    expect(parsed.key_id).toBe('agk_abc12345');
    expect(parsed.secret).toBe('a'.repeat(43));
  });

  it('rejects missing dot', () => {
    expect(() => parseApiKey('agk_abc12345')).toThrowError(
      expect.objectContaining({ status: 401, code: 'invalid_key' }),
    );
  });

  it('rejects bad prefix', () => {
    expect(() => parseApiKey('xyz_abc12345.' + 'a'.repeat(43))).toThrowError(
      expect.objectContaining({ status: 401, code: 'invalid_key' }),
    );
  });
});

describe('encodeKeyCache / decodeKeyCache round-trip', () => {
  it('preserves all fields including key_hash and scopes', () => {
    const c = {
      key_id: 'agk_x',
      account_id: 'a',
      account_status: 'active' as AccountStatus,
      issuing_identity_id: 'i',
      issuing_identity_status: 'active' as IdentityStatus,
      identity_provider: 'github_app',
      identity_subject: '12345',
      identity_display_handle: 'oct',
      identity_assurance_level: 'medium' as const,
      key_hash: Buffer.from('00112233445566778899aabbccddeeff', 'hex'),
      key_pepper_version: 7,
      scopes: ['read', 'self:rotate'],
      tier: 'cold' as const,
      rotation_state: 'active' as RotationState,
      revoked_at: null,
      grace_expires_at: null,
      expires_at: null,
      cached_epoch: 42,
      cached_at: 1000,
      redis_expires_at: 31000,
    };
    const back = decodeKeyCache(encodeKeyCache(c));
    expect(back.key_id).toBe(c.key_id);
    expect(back.key_hash.equals(c.key_hash)).toBe(true);
    expect(back.scopes).toEqual(c.scopes);
    expect(back.cached_epoch).toBe(42);
    expect(back.identity_display_handle).toBe('oct');
  });
});

describe('validateKey (SPEC §5.3.3)', () => {
  let kms: InMemoryKmsAdapter;
  let redis: InMemoryRedisAdapter;
  let pg: FakePg;
  let localCache: LocalCache;
  let secret: Buffer;
  let key_hash: Buffer;
  let deps: ValidateKeyDeps;

  beforeEach(async () => {
    kms = new InMemoryKmsAdapter();
    redis = new InMemoryRedisAdapter();
    pg = new FakePg();
    localCache = new LocalCache();
    secret = randomBytes(32);
    const pepper = await kms.getCurrentPepper();
    key_hash = hmacWithPepper(pepper.data, secret);
    pg.rows.set('agk_abc12345', {
      key_id: 'agk_abc12345',
      account_id: 'acc-1',
      account_status: 'active',
      account_tier: 'cold',
      issued_via_identity_id: 'id-1',
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: '12345',
      identity_display_handle: 'octocat',
      identity_assurance_level: 'medium',
      key_hash,
      key_pepper_version: 1,
      scopes: ['read', 'self:rotate'],
      tier: 'cold',
      rotation_state: 'active',
      revoked_at: null,
      rotation_grace_expires_at: null,
      expires_at: null,
    });
    deps = {
      postgres: fakePgAsAdapter(pg),
      redis,
      kms,
      localCache,
      redis_cache_ttl_seconds: 30,
    };
  });

  function presentedKey(s: Buffer = secret): string {
    return 'agk_abc12345.' + s.toString('base64url');
  }

  it('happy path: returns AgentContext on first call (Postgres lookup)', async () => {
    const ctx = await validateKey(presentedKey(), deps);
    expect(ctx.account_id).toBe('acc-1');
    expect(ctx.key_id).toBe('agk_abc12345');
    expect(ctx.identity.provider).toBe('github_app');
    expect(ctx.has_scope('read')).toBe(true);
    expect(pg.callCount).toBe(1);
  });

  it('second call hits the local cache (no extra Postgres call)', async () => {
    await validateKey(presentedKey(), deps);
    await validateKey(presentedKey(), deps);
    expect(pg.callCount).toBe(1);
  });

  it('Redis-cached entry under same epoch hits without Postgres', async () => {
    // Prime Redis directly, leave local cache empty.
    await validateKey(presentedKey(), deps);
    expect(pg.callCount).toBe(1);
    // Clear local cache; Redis should still serve.
    localCache.clear();
    await validateKey(presentedKey(), deps);
    expect(pg.callCount).toBe(1);
  });

  it('Postgres miss returns 401 key_not_found (RT-3 / RT-25 fallback path)', async () => {
    pg.rows.clear();
    redis = new InMemoryRedisAdapter();
    deps = { ...deps, redis };
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'key_not_found' }),
    );
  });

  it('rejects when account is suspended', async () => {
    pg.rows.get('agk_abc12345')!.account_status = 'suspended';
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'account_suspended' }),
    );
  });

  it('rejects when account is closed (410)', async () => {
    pg.rows.get('agk_abc12345')!.account_status = 'closed';
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 410, code: 'account_closed' }),
    );
  });

  it('rejects when issuing identity is revoked (RT-24 webhook cascade)', async () => {
    pg.rows.get('agk_abc12345')!.issuing_identity_status = 'revoked';
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'identity_revoked' }),
    );
  });

  it('rejects revoked key', async () => {
    pg.rows.get('agk_abc12345')!.rotation_state = 'revoked';
    pg.rows.get('agk_abc12345')!.revoked_at = new Date();
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'key_revoked' }),
    );
  });

  it('rejects rotated key', async () => {
    pg.rows.get('agk_abc12345')!.rotation_state = 'rotated';
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'key_rotated' }),
    );
  });

  it('rejects key whose rotation grace has expired', async () => {
    pg.rows.get('agk_abc12345')!.rotation_state = 'rotating';
    pg.rows.get('agk_abc12345')!.rotation_grace_expires_at = new Date(Date.now() - 1000);
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'rotation_grace_expired' }),
    );
  });

  it('rejects expired key', async () => {
    pg.rows.get('agk_abc12345')!.expires_at = new Date(Date.now() - 1000);
    await expect(validateKey(presentedKey(), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'key_expired' }),
    );
  });

  it('honors injectable clock for key_expired (deterministic time travel)', async () => {
    // expires_at is 1 hour from real-now; with the injected clock running
    // 2 hours ahead, validateKey must reject.
    const realNow = Date.now();
    pg.rows.get('agk_abc12345')!.expires_at = new Date(realNow + 60 * 60 * 1000);
    const fastForwardDeps = { ...deps, now: () => realNow + 2 * 60 * 60 * 1000 };
    await expect(validateKey(presentedKey(), fastForwardDeps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'key_expired' }),
    );
  });

  it('honors injectable clock for rotation_grace_expired', async () => {
    const realNow = Date.now();
    pg.rows.get('agk_abc12345')!.rotation_state = 'rotating';
    pg.rows.get('agk_abc12345')!.rotation_grace_expires_at = new Date(
      realNow + 30 * 60 * 1000,
    );
    const fastForwardDeps = {
      ...deps,
      now: () => realNow + 60 * 60 * 1000,
    };
    await expect(validateKey(presentedKey(), fastForwardDeps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'rotation_grace_expired' }),
    );
  });

  it('rejects wrong secret with invalid_secret (constant-time hash check)', async () => {
    await expect(validateKey(presentedKey(randomBytes(32)), deps)).rejects.toThrowError(
      expect.objectContaining({ status: 401, code: 'invalid_secret' }),
    );
  });

  it('cached entry is invalidated when epoch advances (RT-26)', async () => {
    // First call populates Redis under epoch 0.
    await validateKey(presentedKey(), deps);
    expect(pg.callCount).toBe(1);

    // Bump epoch on Redis (simulates a revoke writing the new epoch).
    await redis.proposeEpoch(7);
    // Local cache still has the old entry; it should be ignored (cached_epoch=0 != 7).
    await validateKey(presentedKey(), deps);
    expect(pg.callCount).toBe(2);
  });

  it('still validates under dual-pepper rotation (key issued v1, KMS rotated to v2)', async () => {
    // Rotate AFTER the row was written with v1; verifyKey walks v1 in dual window.
    kms.rotate();
    await validateKey(presentedKey(), deps);
    // No throw — happy path under rotation.
  });

  it('does not blow up when Redis is unavailable for SET (best-effort cache write)', async () => {
    // Wrap the in-memory redis with a proxy that throws on `set`. All other
    // methods pass through to the real adapter (so the GET that precedes the
    // Postgres lookup still works as expected).
    const flaky = new Proxy(redis, {
      get(target, prop, receiver) {
        if (prop === 'set') {
          return async () => {
            throw new Error('redis-down');
          };
        }
        return Reflect.get(target, prop, receiver);
      },
    });
    deps = { ...deps, redis: flaky };
    const ctx = await validateKey(presentedKey(), deps);
    expect(ctx.account_id).toBe('acc-1');
  });
});
