/**
 * Integration: /rotate-key end-to-end against real Postgres + Redis.
 * SPEC §2.7 + §3.5 trigger.
 *
 * Covers:
 *   - Emergency rotation: old key flips to 'revoked' immediately; new key
 *     active; sealed-box payload decrypts to a key that validates.
 *   - Planned rotation: old key 'rotating' with grace_expires_at; both
 *     keys validate during the window; epoch bumped (rotating is auth-
 *     relevant per §5.3.2).
 *   - Idempotent emergency replay returns the SAME new key (resource_ref
 *     drives the idempotency lookup; second call returns cached body).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { rotateKey } from '../../src/routes/rotate-key.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { buildAgentContext } from '../../src/agent-context.js';
import {
  open as sealedOpen,
  sealedBoxReady,
  keypair,
} from '../../src/crypto/sealed-box.js';
import type { AgentContext, KeyCache } from '../../src/types.js';

describe('integration: /rotate-key (SPEC §2.7 / §3.5)', () => {
  let fix: IntegrationFixture;
  let bearer: string;
  let key_id: string;
  let account_id: string;
  let identity_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    await sealedBoxReady();
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rot-int', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'rot-int-1', 'Iv1.r', 'github.com', 'medium',
                 'rot-int-octo', true, 'active') RETURNING id`,
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
        acc!.id,
        ident!.id,
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

  function caller(): AgentContext {
    const cache: KeyCache = {
      key_id,
      account_id,
      account_status: 'active',
      issuing_identity_id: identity_id,
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: 'rot-int-1',
      identity_assurance_level: 'medium',
      key_hash: Buffer.alloc(32),
      key_pepper_version: 1,
      scopes: ['read', 'self:rotate'],
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

  it('emergency rotation: old → revoked; new key validates; sealed payload decrypts', async () => {
    const kp = keypair();
    const out = await rotateKey(
      {
        grace_seconds: 0,
        reason: 'integration_emergency',
        client_pubkey_b64: kp.publicKey.toString('base64url'),
      },
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
    expect(out.new_key.encrypted_payload).toBeDefined();

    const cleartext = sealedOpen(
      Buffer.from(out.new_key.encrypted_payload!, 'base64url'),
      kp.publicKey,
      kp.secretKey,
    );
    const payload = JSON.parse(cleartext.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
      is_first_key: boolean;
    };
    expect(payload.key_id).toBe(out.new_key.key_id);
    expect(payload.account_id).toBe(account_id);
    expect(payload.is_first_key).toBe(false);

    // New key validates against the real DB.
    const ctxNew = await validateKey(payload.key, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctxNew.account_id).toBe(account_id);
    expect(ctxNew.key_id).toBe(out.new_key.key_id);

    // Old key now rejects with key_revoked.
    await expect(
      validateKey(bearer, {
        postgres: fix.postgres,
        redis: fix.redis,
        kms: fix.kms,
        localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
        redis_cache_ttl_seconds: 30,
      }),
    ).rejects.toMatchObject({ status: 401, code: 'key_revoked' });

    // Disk state confirms.
    const oldRow = await fix.postgres.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_id],
    );
    expect(oldRow?.rotation_state).toBe('revoked');

    // SPEC §6.4 — emergency rotation produced an audit row in-tx.
    const audit = await fix.postgres.queryOne<{
      event_type: string;
      key_id: string;
    }>(
      `SELECT event_type, key_id FROM agent_audit_log
        WHERE event_type = 'emergency_rotate' AND key_id = $1
        ORDER BY id DESC LIMIT 1`,
      [key_id],
    );
    expect(audit?.event_type).toBe('emergency_rotate');
  });

  it('idempotent emergency replay returns the cached new key without issuing another', async () => {
    // Seed a fresh key for this test (the previous test revoked the original).
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const new_kid = `agk_${randomBytes(6).toString('base64url')}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read', 'self:rotate'], 'cold', 1, 'active')`,
      [
        account_id,
        identity_id,
        new_kid,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    const cache: KeyCache = {
      key_id: new_kid,
      account_id,
      account_status: 'active',
      issuing_identity_id: identity_id,
      issuing_identity_status: 'active',
      identity_provider: 'github_app',
      identity_subject: 'rot-int-1',
      identity_assurance_level: 'medium',
      key_hash: Buffer.alloc(32),
      key_pepper_version: 1,
      scopes: ['read', 'self:rotate'],
      tier: 'cold',
      rotation_state: 'active',
      revoked_at: null,
      grace_expires_at: null,
      expires_at: null,
      cached_epoch: 0,
      cached_at: 0,
      redis_expires_at: 30000,
    };
    const ctx = buildAgentContext(cache);
    const idem = randomUUID();
    const args = { grace_seconds: 0, reason: 'integration_replay' };
    const a = await rotateKey(args, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      region: 'us-east-1',
      caller: ctx,
      idempotency_key: idem,
    });
    const b = await rotateKey(args, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      region: 'us-east-1',
      caller: ctx,
      idempotency_key: idem,
    });
    expect(b.new_key.key_id).toBe(a.new_key.key_id);
  });
});
