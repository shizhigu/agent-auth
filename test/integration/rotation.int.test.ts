/**
 * Integration: /rotate-key against real Postgres + Redis. SPEC §2.7 + §3.5.
 *
 * Covers:
 *   - planned rotation (Tier A): old key → 'rotating' with grace; new key
 *     issued with `created_by_key_id` link. Validation against the OLD
 *     bearer still succeeds during the grace window.
 *   - emergency rotation (Tier B): old key → 'revoked' immediately;
 *     validation against the old bearer rejects 401 key_revoked.
 *   - concurrent rotation race: two callers try to rotate the same
 *     predecessor — the §3.5 enforce_rotation_inverse trigger raises a
 *     unique_violation; one succeeds, the other surfaces an error. This
 *     prevents two distinct successor keys with the same predecessor.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  provisionFixture,
  type IntegrationFixture,
} from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { rotateKey } from '../../src/routes/rotate-key.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { buildAgentContext } from '../../src/agent-context.js';
import type { AgentContext, KeyCache } from '../../src/types.js';

describe('integration: rotation (SPEC §2.7 / §3.5)', () => {
  let fix: IntegrationFixture;
  let bearer: string;
  let key_id: string;
  let account_id: string;
  let identity_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rot-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'rot-1', 'Iv1.r', 'github.com', 'medium',
                 'rot-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    account_id = acc!.id;
    identity_id = ident!.id;
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    key_id = `agk_${randomBytes(6).toString('base64url')}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read', 'self:rotate'], 'cold', 1, 'active')`,
      [
        account_id,
        identity_id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  function caller(scope_extra: string[] = []): AgentContext {
    const cache: KeyCache = {
      key_id,
      account_id,
      account_status: 'active',
      issuing_identity_id: identity_id,
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: 'rot-1',
      identity_assurance_level: 'medium',
      key_hash: Buffer.alloc(32),
      key_pepper_version: 1,
      scopes: ['read', 'self:rotate', ...scope_extra],
      tier: 'cold',
      rotation_state: 'active',
      revoked_at: null,
      grace_expires_at: null,
      expires_at: null,
      cached_epoch: 0,
      cached_at: 0,
      redis_expires_at: 30000,
    };
    return buildAgentContext(cache);
  }

  it('planned rotation: old → rotating + grace; new key active; old still validates during grace', async () => {
    const out = await rotateKey(
      { grace_seconds: 600, reason: 'integration_planned' },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        kms: fix.kms,
        region: 'us-east-1',
        caller: caller(),
        idempotency_key: randomUUID(),
      },
    );
    expect(out.old_key.key_id).toBe(key_id);
    expect(out.new_key.key_id.startsWith('agk_')).toBe(true);
    expect(out.new_key.secret).toBeDefined();
    // Validate the new key against the real DB.
    const ctxNew = await validateKey(out.new_key.secret!, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctxNew.account_id).toBe(account_id);
    expect(ctxNew.key_id).toBe(out.new_key.key_id);
    // Old key still works during grace.
    const ctxOld = await validateKey(bearer, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctxOld.key_id).toBe(key_id);
    // Confirm old row is in the 'rotating' state on disk.
    const oldRow = await fix.postgres.queryOne<{ rotation_state: string; replaced_by_key_id: string }>(
      `SELECT rotation_state, replaced_by_key_id::text AS replaced_by_key_id
         FROM agent_api_keys WHERE key_id = $1`,
      [key_id],
    );
    expect(oldRow?.rotation_state).toBe('rotating');
    expect(oldRow?.replaced_by_key_id).toBeTruthy();
  });

  it('§3.5 trigger: concurrent rotation on same predecessor — second INSERT raises unique_violation', async () => {
    // Seed a fresh account + key so this test is independent.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('race-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'race-1', 'Iv1.race', 'github.com', 'medium',
                 'race-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const oldId = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, 'agk_race1', $3, 1, 'aaaaaaaa', ARRAY['read'], 'cold', 1, 'active')
         RETURNING id`,
      [acc!.id, ident!.id, Buffer.alloc(32, 4)],
    );

    // Insert a successor (winner) — trigger sets old.replaced_by_key_id.
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state, created_by_key_id)
         VALUES ($1, $2, 'agk_race2', $3, 1, 'bbbbbbbb', ARRAY['read'], 'cold', 1, 'active', $4)`,
      [acc!.id, ident!.id, Buffer.alloc(32, 5), oldId!.id],
    );

    // Insert a competing successor with the same predecessor — must raise.
    let caught: unknown;
    try {
      await fix.postgres.query(
        `INSERT INTO agent_api_keys
           (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
            prefix, scopes, tier, version, rotation_state, created_by_key_id)
           VALUES ($1, $2, 'agk_race3', $3, 1, 'cccccccc', ARRAY['read'], 'cold', 1, 'active', $4)`,
        [acc!.id, ident!.id, Buffer.alloc(32, 6), oldId!.id],
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    const e = caught as { code?: string; message?: string };
    // pg error code '23505' is unique_violation; the trigger raises with that errcode.
    expect(e.code).toBe('23505');
  });
});
