/**
 * Chaos: KMS unavailable. SPEC §12.4 / RT-22.
 *
 * The lib's HMAC-pepper validation REQUIRES KMS to fetch the pepper for
 * the configured key_pepper_version. If KMS is unreachable, validateKey
 * MUST fail closed — never silently accept. The test wires a broken
 * KmsAdapter into validateKey alongside healthy Postgres + Redis and
 * confirms acceptance is denied for both:
 *   - the correct secret (cannot be verified without the pepper)
 *   - a wrong secret (would otherwise be 401, but with KMS down should
 *     surface a 5xx because we can't tell the difference)
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  provisionFixture,
  type IntegrationFixture,
} from '../integration/setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import type { KmsAdapter, EncryptedBlob, PepperMaterial } from '../../src/storage/kms-adapter.js';

class BrokenKmsAdapter implements KmsAdapter {
  async getCurrentPepper(): Promise<PepperMaterial> {
    throw new Error('kms_unavailable');
  }
  async getPepperByVersion(): Promise<PepperMaterial> {
    throw new Error('kms_unavailable');
  }
  async acceptedVersions(): Promise<ReadonlyArray<number>> {
    throw new Error('kms_unavailable');
  }
  async encryptDevice(): Promise<EncryptedBlob> {
    throw new Error('kms_unavailable');
  }
  async decryptDevice(): Promise<Buffer> {
    throw new Error('kms_unavailable');
  }
}

describe('chaos: KMS unavailable (SPEC §12.4 / RT-22)', () => {
  let fix: IntegrationFixture;
  let bearer: string;
  let bearer_bad: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('kms-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'kms-1', 'Iv1.k', 'github.com', 'medium',
                 'kms-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const key_id = `agk_${randomBytes(6).toString('base64url')}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;
    bearer_bad = `${key_id}.${randomBytes(32).toString('base64url')}`;
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  function deps(kms: KmsAdapter) {
    return {
      postgres: fix.postgres,
      redis: fix.redis,
      kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    };
  }

  it('control: working KMS accepts the correct secret', async () => {
    const ctx = await validateKey(bearer, deps(fix.kms));
    expect(ctx.identity.subject).toBe('kms-1');
  });

  it('RT-22: KMS down — correct secret no longer accepts (fail closed)', async () => {
    let outcome: 'returned' | 'threw' = 'threw';
    let returned: unknown;
    let thrown: unknown;
    try {
      returned = await validateKey(bearer, deps(new BrokenKmsAdapter()));
      outcome = 'returned';
    } catch (err) {
      thrown = err;
    }
    if (outcome === 'returned') {
      // Catastrophic invariant violation: lib accepted without verifying.
      expect(returned).toBeUndefined();
    }
    expect(thrown).toBeDefined();
    // Validation must surface either AgentAuthError(invalid_secret/...) OR
    // raw error from KMS — never silent success.
    const e = thrown as { code?: string; message?: string; status?: number };
    expect(e.code === 'invalid_secret' || typeof e.message === 'string').toBe(true);
  });

  it('RT-22: KMS down — wrong secret never accepts', async () => {
    let outcome: 'returned' | 'threw' = 'threw';
    let returned: unknown;
    let thrown: unknown;
    try {
      returned = await validateKey(bearer_bad, deps(new BrokenKmsAdapter()));
      outcome = 'returned';
    } catch (err) {
      thrown = err;
    }
    if (outcome === 'returned') {
      expect(returned).toBeUndefined();
    }
    expect(thrown).toBeDefined();
  });
});
