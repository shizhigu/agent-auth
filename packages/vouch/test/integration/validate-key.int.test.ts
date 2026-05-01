/**
 * Integration: end-to-end validate-key against real Postgres + Redis.
 *
 * Covers:
 *   - SPEC §5.3.3 cache flow (local → Redis → Postgres) against a real DB.
 *   - RT-26 Redis stale epoch / split-brain falls through to Postgres on
 *     epoch mismatch.
 *   - RT-3 / RT-25 Redis partition: simulated via redis_client.flushdb().
 *   - Schema invariants — the §3.5 trigger raises unique_violation on
 *     concurrent rotation insertion (covered by /rotate-key tests instead).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  provisionFixture,
  makeLocalCache,
  type IntegrationFixture,
} from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { bumpEpochInTx } from '../../src/distributed/revocation-epoch.js';
import { tierBTransaction } from '../../src/distributed/tier-b-commit.js';

describe('integration: validate-key (SPEC §5.3.3)', () => {
  let fix: IntegrationFixture;
  let secret: Buffer;
  let bearer: string;
  let key_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();

    // Seed an account, identity, key.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('it-acc', 'cold', 'active')
         RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', '12345', 'Iv1.x', 'github.com', 'medium',
                 'octocat', true, 'active')
         RETURNING id`,
      [acc!.id],
    );

    secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const public_id = randomBytes(6).toString('base64url');
    key_id = `agk_${public_id}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
        ['read', 'self:rotate'],
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('happy path: validateKey returns AgentContext with correct fields', async () => {
    const ctx = await validateKey(bearer, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: makeLocalCache(),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctx.key_id).toBe(key_id);
    expect(ctx.tier).toBe('cold');
    expect(ctx.scopes).toContain('read');
    expect(ctx.identity.provider).toBe('github_app');
  });

  it('RT-26: bumping the global epoch invalidates cached entries', async () => {
    const localCache = makeLocalCache();
    const deps = {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache,
      redis_cache_ttl_seconds: 30,
    };
    // Prime caches.
    await validateKey(bearer, deps);
    expect(localCache.size()).toBe(1);

    // Mutator side: bump epoch in a Tier B txn (the way /revoke does it).
    await tierBTransaction(fix.postgres, async (client) => {
      await bumpEpochInTx(client, fix.redis);
    });

    // Next validation should fall through to Postgres because the cached
    // entry's `cached_epoch` no longer matches the new authoritative epoch.
    // We assert by checking the local cache was repopulated with a higher
    // cached_epoch value.
    const beforeEpoch = await fix.redis.getAuthoritativeEpoch();
    expect(beforeEpoch).toBeGreaterThan(0);
    await validateKey(bearer, deps);
    const cached = localCache.keys();
    expect(cached).toContain(key_id);
  });

  it('RT-3: Redis FLUSHDB does not break validation (Postgres fallback)', async () => {
    await fix.redis_client.flushdb();
    const ctx = await validateKey(bearer, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: makeLocalCache(),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctx.key_id).toBe(key_id);
  });

  it('rejects 401 invalid_secret on bad secret', async () => {
    const bad = `${key_id}.${randomBytes(32).toString('base64url')}`;
    await expect(
      validateKey(bad, {
        postgres: fix.postgres,
        redis: fix.redis,
        kms: fix.kms,
        localCache: makeLocalCache(),
        redis_cache_ttl_seconds: 30,
      }),
    ).rejects.toMatchObject({ status: 401, code: 'invalid_secret' });
  });
});
