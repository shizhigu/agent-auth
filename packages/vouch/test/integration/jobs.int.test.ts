/**
 * Integration: background jobs against real Postgres + Redis. SPEC §3.6
 * (reaper) + §5.3.6 (reconcile_account_key_sets).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { reapRegistrationSessions } from '../../src/jobs/reaper.js';
import { reconcileAccountKeySets } from '../../src/jobs/reconcile-redis-sets.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { KEY_PREFIX_ACCOUNT_KEYS } from '../../src/storage/redis-adapter.js';

describe('integration: background jobs (SPEC §3.6 / §5.3.6)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('reapRegistrationSessions deletes sessions ≥1h past expires_at', async () => {
    const now = new Date();
    const oldExpires = new Date(now.getTime() - 2 * 60 * 60 * 1000); // 2h old
    const freshExpires = new Date(now.getTime() + 60 * 1000); // future
    // Insert one expired session and one fresh session.
    await fix.postgres.query(
      `INSERT INTO agent_registration_sessions
         (poll_token, nonce, pkce_verifier, pkce_challenge, audience,
          expected_provider, redirect_uri, kind, client_pubkey, status, expires_at)
       VALUES
         ($1, $2, 'v', 'c', 'aud', 'github_app', 'https://r', 'register', $3, 'expired', $4),
         ($5, $6, 'v2', 'c2', 'aud', 'github_app', 'https://r', 'register', $3, 'pending', $7)`,
      [
        'pak_' + 'A'.repeat(43),
        randomBytes(32).toString('base64url'),
        Buffer.alloc(32),
        oldExpires,
        'pak_' + 'B'.repeat(43),
        randomBytes(32).toString('base64url'),
        freshExpires,
      ],
    );
    const result = await reapRegistrationSessions(fix.postgres, now);
    expect(result.registration_sessions_deleted).toBeGreaterThanOrEqual(1);
    const remaining = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_registration_sessions
        WHERE poll_token IN ($1, $2)`,
      ['pak_' + 'A'.repeat(43), 'pak_' + 'B'.repeat(43)],
    );
    // Only the fresh one survives.
    expect(remaining?.count).toBe('1');
  });

  it('reconcileAccountKeySets adds missing + removes stale Redis SET entries', async () => {
    // Seed: account active in last 7 days; 2 active keys + 1 revoked.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status, updated_at)
         VALUES ('rec-acc', 'cold', 'active', now()) RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'rec-1', 'Iv1.r', 'github.com', 'medium',
                 'rec-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const pepper = await fix.kms.getCurrentPepper();
    const keys: string[] = [];
    for (let i = 0; i < 3; i++) {
      const secret = randomBytes(32);
      const key_hash = hmacWithPepper(pepper.data, secret);
      const key_id = `agk_rec_${i}`;
      const state = i < 2 ? 'active' : 'revoked';
      await fix.postgres.query(
        `INSERT INTO agent_api_keys
           (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
            prefix, scopes, tier, version, rotation_state, revoked_at)
           VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1,
                   $7::rotation_state_enum,
                   CASE WHEN $7::rotation_state_enum = 'revoked'::rotation_state_enum
                        THEN now() ELSE NULL END)`,
        [acc!.id, ident!.id, key_id, key_hash, pepper.version, secret.toString('base64url').slice(0, 8), state],
      );
      keys.push(key_id);
    }

    // Plant a stale entry in Redis for this account (key_id that no
    // longer exists in DB) and skip seeding the legitimate active keys.
    const setKey = KEY_PREFIX_ACCOUNT_KEYS + acc!.id;
    await fix.redis.sadd(setKey, 'agk_phantom_stale');

    const result = await reconcileAccountKeySets({
      postgres: fix.postgres,
      redis: fix.redis,
    });
    expect(result.inspected).toBeGreaterThanOrEqual(1);
    // 2 active keys were missing → SADDed.
    expect(result.added).toBeGreaterThanOrEqual(2);
    // 1 phantom was stale → SREMed.
    expect(result.removed).toBeGreaterThanOrEqual(1);

    const members = new Set(await fix.redis.smembers(setKey));
    expect(members.has('agk_rec_0')).toBe(true);
    expect(members.has('agk_rec_1')).toBe(true);
    // Revoked key is NOT included (rotation_state filter).
    expect(members.has('agk_rec_2')).toBe(false);
    // Phantom is gone.
    expect(members.has('agk_phantom_stale')).toBe(false);
  });
});
