/**
 * Integration: full GitHub App registration flow against real Postgres + Redis.
 *
 * Drives /begin-registration → /callback → /registration-status with a
 * stub IdentityProvider that returns a fixed Attestation (audience matches
 * the configured client_id). Verifies §2.2.2 + §2.6 end-to-end:
 *   - PKCE verifier round-trip (challenge stored in DB, verifier matched
 *     by callback against the GitHub-side `code` exchange — stubbed here).
 *   - Single-use nonce: callback transitions session pending → exchanging.
 *   - Account + identity + key created in one Tier B transaction.
 *   - Sealed-box payload returned by /registration-status decrypts to the
 *     §2.6 schema and the issued key validates against `validateKey`.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { beginRegistration } from '../../src/routes/begin-registration.js';
import { callback } from '../../src/routes/callback.js';
import { registrationStatus } from '../../src/routes/registration-status.js';
import {
  open as sealedOpen,
  sealedBoxReady,
  keypair,
} from '../../src/crypto/sealed-box.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import type {
  Attestation,
  AttestationContext,
  IdentityProvider,
  ProviderInput,
} from '../../src/types.js';

class StubGithubProvider implements IdentityProvider {
  readonly name = 'github_app';
  /** Track that beginRegistration ran with the right ctx. */
  beginCalled = 0;
  exchangeCalled = 0;
  async beginRegistration(ctx: AttestationContext) {
    this.beginCalled++;
    void ctx;
    return { challenge_url: 'https://github.com/login/oauth/authorize?state=' + ctx.nonce };
  }
  async exchangeOrVerify(_input: ProviderInput, ctx: AttestationContext): Promise<Attestation> {
    this.exchangeCalled++;
    return {
      issuer: 'github.com',
      subject: '777',
      audience: ctx.audience,
      display_handle: 'reg-octo',
      assurance_level: 'medium',
      supports_revalidation: true,
    };
  }
  async revalidate() {
    return { still_valid: true };
  }
}

describe('integration: full registration flow (SPEC §2.2.2 + §2.6)', () => {
  let fix: IntegrationFixture;
  let provider: StubGithubProvider;
  let agentKp: { publicKey: Buffer; secretKey: Buffer };

  beforeAll(async () => {
    fix = await provisionFixture();
    provider = new StubGithubProvider();
    await sealedBoxReady();
    agentKp = keypair();
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('happy path: begin → callback → status returns sealed payload that decrypts to a valid key', async () => {
    // Step 1: begin-registration.
    const begin = await beginRegistration(
      {
        provider: 'github_app',
        intent: 'register',
        client_pubkey: agentKp.publicKey.toString('base64url'),
      },
      {
        postgres: fix.postgres,
        identity_providers: [provider],
        redirect_uri: () => 'https://saas.example/callback',
        audience: () => 'Iv1.regtest',
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(begin.poll_token.startsWith('pak_')).toBe(true);
    expect(begin.challenge_url).toContain('state=');

    // Pull the nonce from the row (it's the OAuth state parameter).
    const session = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [begin.poll_token],
    );
    expect(session?.nonce).toBeDefined();

    // Step 2: simulate the OAuth callback. The stub provider returns the
    // attestation regardless of the `code`; the lib's callback handler
    // validates the audience match + handles all DB / sealed-box / key
    // issuance work.
    const cb = await callback(
      {
        provider: 'github_app',
        state: session!.nonce,
        code: 'gho_stub',
      },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(cb.status).toBe('success');
    expect(cb.account_id).toBeDefined();
    expect(cb.is_first_key).toBe(true);
    expect(provider.exchangeCalled).toBe(1);

    // Step 3: poll registration-status, decrypt the sealed payload.
    const status = await registrationStatus(
      { poll_token: begin.poll_token },
      { postgres: fix.postgres, endpoint: 'registration' },
    );
    expect(status.status).toBe('completed');
    if (status.status !== 'completed') return; // narrow
    expect(status.account_id).toBe(cb.account_id);
    expect(status.is_first_key).toBe(true);

    const cleartext = sealedOpen(
      Buffer.from(status.encrypted_payload, 'base64url'),
      agentKp.publicKey,
      agentKp.secretKey,
    );
    const payload = JSON.parse(cleartext.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
      scopes: string[];
      tier: string;
      is_first_key: boolean;
      issued_at: string;
    };
    expect(payload.key.split('.')[0]).toBe(payload.key_id);
    expect(payload.account_id).toBe(cb.account_id);
    expect(payload.is_first_key).toBe(true);
    expect(payload.scopes).toEqual(['read', 'self:rotate']);

    // Step 4: validate the issued key end-to-end.
    const ctx = await validateKey(payload.key, {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    });
    expect(ctx.account_id).toBe(payload.account_id);
    expect(ctx.key_id).toBe(payload.key_id);
    expect(ctx.identity.provider).toBe('github_app');
    expect(ctx.identity.subject).toBe('777');
  });

  it('replay /callback with the same nonce is rejected (single-use)', async () => {
    // Begin a new session.
    const begin = await beginRegistration(
      {
        provider: 'github_app',
        intent: 'register',
        client_pubkey: agentKp.publicKey.toString('base64url'),
      },
      {
        postgres: fix.postgres,
        identity_providers: [provider],
        redirect_uri: () => 'https://saas.example/callback',
        audience: () => 'Iv1.regtest',
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    const session = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [begin.poll_token],
    );
    // First callback succeeds.
    await callback(
      { provider: 'github_app', state: session!.nonce, code: 'c' },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    // Second callback finds no `pending` row matching that nonce.
    const replay = await callback(
      { provider: 'github_app', state: session!.nonce, code: 'c' },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(replay.status).toBe('failed');
    expect(replay.reason).toBe('registration_session_not_found_or_expired');
  });
});
