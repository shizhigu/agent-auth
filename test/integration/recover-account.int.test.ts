/**
 * Integration: full account recovery flow against real DB. SPEC §2.9 + §2.2.2 case C.
 *
 * Scenario:
 *   1. Account + identity + key already in DB.
 *   2. GitHub fires github_app_authorization revoked → identity revoked
 *      via `webhook` source; cascade revokes the key; account suspended
 *      (no other primary identity remains, then we lift the suspension
 *      since the recover flow handles only the identity).
 *   3. /recover-account (intent='recover', target_account_id) mints a
 *      pkr_<token>.
 *   4. /callback (case C: identity revoked by webhook → re-activate)
 *      issues a new key and seals it.
 *   5. /recover-account-status returns the sealed payload; we decrypt
 *      and validate the new key.
 *
 * Verifies the full §2.9 flow (re-activation + new key issuance + the
 * account_id binding from /begin-registration is preserved at /callback).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { recoverAccount } from '../../src/routes/recover-account.js';
import { recoverAccountStatus } from '../../src/routes/recover-account-status.js';
import { callback } from '../../src/routes/callback.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import {
  open as sealedOpen,
  sealedBoxReady,
  keypair,
} from '../../src/crypto/sealed-box.js';
import type {
  Attestation,
  AttestationContext,
  IdentityProvider,
  ProviderInput,
} from '../../src/types.js';

class StubGithubProvider implements IdentityProvider {
  readonly name = 'github_app';
  async beginRegistration(ctx: AttestationContext) {
    return { challenge_url: `https://github.com/login/oauth/authorize?state=${ctx.nonce}` };
  }
  async exchangeOrVerify(_input: ProviderInput, ctx: AttestationContext): Promise<Attestation> {
    return {
      issuer: 'github.com',
      subject: 'rec-int-1',
      audience: ctx.audience,
      display_handle: 'rec-int-octo',
      assurance_level: 'medium',
      supports_revalidation: true,
    };
  }
  async revalidate() {
    return { still_valid: true };
  }
}

describe('integration: /recover-account full flow (SPEC §2.9 / §2.2.2 case C)', () => {
  let fix: IntegrationFixture;
  let provider: StubGithubProvider;
  let agentKp: { publicKey: Buffer; secretKey: Buffer };
  let account_id: string;
  let identity_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    await sealedBoxReady();
    agentKp = keypair();
    provider = new StubGithubProvider();

    // Seed: account + identity (subject 'rec-int-1') + active key.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rec-int', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'rec-int-1', 'Iv1.recint', 'github.com', 'medium',
                 'rec-int-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    account_id = acc!.id;
    identity_id = ident!.id;
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        `agk_rec_pre`,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );

    // Simulate the webhook revocation that triggers the recovery scenario:
    // identity flipped to revoked with revocation_source='webhook' (the
    // case C re-activation path applies).
    await fix.postgres.query(
      `UPDATE agent_identities
          SET status = 'revoked', revoked_at = now(),
              revoked_reason = 'user_revoked_app_access',
              revocation_source = 'webhook'
        WHERE id = $1`,
      [identity_id],
    );
    await fix.postgres.query(
      `UPDATE agent_api_keys
          SET rotation_state = 'revoked', revoked_at = now(),
              revoked_reason = 'primary_identity_revoked'
        WHERE key_id = 'agk_rec_pre'`,
    );
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('happy path: /recover-account → /callback (case C reactivate) → /recover-account-status returns valid sealed payload', async () => {
    // Step 1: /recover-account binds the recovery session to target_account_id.
    const begin = await recoverAccount(
      {
        provider: 'github_app',
        account_id,
        client_pubkey: agentKp.publicKey.toString('base64url'),
      },
      {
        postgres: fix.postgres,
        identity_providers: [provider],
        redirect_uri: () => 'https://saas.example/callback',
        audience: () => 'Iv1.recint',
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(begin.poll_token.startsWith('pkr_')).toBe(true);

    // Look up the freshly-minted nonce (= OAuth state).
    const session = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [begin.poll_token],
    );
    expect(session?.nonce).toBeDefined();

    // Step 2: simulate the OAuth callback. The provider returns the same
    // subject the seed identity has, so /callback finds the (revoked,
    // webhook-sourced) row and re-activates per case C.
    const cb = await callback(
      {
        provider: 'github_app',
        state: session!.nonce,
        code: 'gho_recover',
      },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(cb.status).toBe('success');
    expect(cb.account_id).toBe(account_id);
    expect(cb.is_first_key).toBe(false);

    // Identity row is now active again, with revoked_* cleared.
    const ident = await fix.postgres.queryOne<{
      status: string;
      revoked_at: Date | null;
      revocation_source: string | null;
    }>(
      `SELECT status, revoked_at, revocation_source FROM agent_identities WHERE id = $1`,
      [identity_id],
    );
    expect(ident?.status).toBe('active');
    expect(ident?.revoked_at).toBeNull();
    expect(ident?.revocation_source).toBeNull();

    // Step 3: /recover-account-status returns the sealed payload.
    const status = await recoverAccountStatus(
      { poll_token: begin.poll_token },
      { postgres: fix.postgres },
    );
    expect(status.status).toBe('completed');
    if (status.status !== 'completed') return;
    expect(status.account_id).toBe(account_id);

    const cleartext = sealedOpen(
      Buffer.from(status.encrypted_payload, 'base64url'),
      agentKp.publicKey,
      agentKp.secretKey,
    );
    const payload = JSON.parse(cleartext.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
      is_first_key: boolean;
    };
    expect(payload.account_id).toBe(account_id);
    expect(payload.is_first_key).toBe(false); // recover ≠ register

    // Step 4: validate the recovered key against the DB.
    const ctx = await validateKey(payload.key, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctx.account_id).toBe(account_id);
    expect(ctx.identity.subject).toBe('rec-int-1');

    // Old (pre-revocation) key remains revoked (recover does NOT
    // resurrect old keys per §2.9 step 6).
    const old = await fix.postgres.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      ['agk_rec_pre'],
    );
    expect(old?.rotation_state).toBe('revoked');
  });
});
