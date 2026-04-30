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
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { beginRegistration } from '../../src/routes/begin-registration.js';
import { callback } from '../../src/routes/callback.js';
import { recoverAccount } from '../../src/routes/recover-account.js';
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

    // SPEC §6.4 — callback success emits an audit row in-tx.
    if (cb.status === 'success') {
      const audit = await fix.postgres.queryOne<{ event_type: string }>(
        `SELECT event_type FROM agent_audit_log
          WHERE event_type = 'register_callback_success'
            AND account_id = $1::uuid
          ORDER BY id DESC LIMIT 1`,
        [cb.account_id],
      );
      expect(audit?.event_type).toBe('register_callback_success');
    }

    // Step 3: poll registration-status, decrypt the sealed payload.
    const status = await registrationStatus(
      { poll_token: begin.poll_token },
      { postgres: fix.postgres, endpoint: 'registration' },
    );
    expect(status.status).toBe('completed');
    if (status.status !== 'completed') return; // narrow
    expect(status.account_id).toBe(cb.account_id);
    expect(status.is_first_key).toBe(true);
    expect(status.encrypted_payload).not.toBeNull();

    const cleartext = sealedOpen(
      Buffer.from(status.encrypted_payload!, 'base64url'),
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

  it('RT-31: audience mismatch — provider returns Iv1.OTHER, session bound to Iv1.regtest → audience_mismatch', async () => {
    // Provider that lies about audience (returns a different one than the
    // session was bound to). Models a token that crossed tenants in transit.
    const lyingProvider: IdentityProvider = {
      name: 'github_app',
      async beginRegistration(ctx) {
        return { challenge_url: `https://github.com/login/oauth/authorize?state=${ctx.nonce}` };
      },
      async exchangeOrVerify(_input, _ctx): Promise<Attestation> {
        return {
          issuer: 'github.com',
          subject: 'rt31-aud',
          audience: 'Iv1.OTHER', // mismatch — session was bound to Iv1.regtest
          display_handle: 'rt31-aud',
          assurance_level: 'medium',
          supports_revalidation: true,
        };
      },
      async revalidate() {
        return { still_valid: true };
      },
    };

    const begin = await beginRegistration(
      {
        provider: 'github_app',
        intent: 'register',
        client_pubkey: agentKp.publicKey.toString('base64url'),
      },
      {
        postgres: fix.postgres,
        identity_providers: [lyingProvider],
        redirect_uri: () => 'https://saas.example/callback',
        audience: () => 'Iv1.regtest',
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    const session = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [begin.poll_token],
    );

    const cb = await callback(
      { provider: 'github_app', state: session!.nonce, code: 'gho_stub' },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [lyingProvider],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(cb.status).toBe('failed');
    if (cb.status === 'failed') {
      expect(cb.reason).toBe('audience_mismatch');
    }
    // Session row marked failed with audience_mismatch as status_message.
    const failed = await fix.postgres.queryOne<{ status: string; status_message: string }>(
      `SELECT status, status_message FROM agent_registration_sessions
        WHERE poll_token = $1`,
      [begin.poll_token],
    );
    expect(failed?.status).toBe('failed');
    expect(failed?.status_message).toBe('audience_mismatch');
    // No identity / account / api_keys rows created for the lying subject.
    const idCount = await fix.postgres.queryOne<{ c: string }>(
      `SELECT count(*)::text AS c FROM agent_identities WHERE subject = $1`,
      ['rt31-aud'],
    );
    expect(Number(idCount?.c ?? '0')).toBe(0);
  });

  it('RT-31: cross-tenant recovery — recover into account B with identity that belongs to account A → identity_account_mismatch', async () => {
    // Pre-seed account A + identity I (subject=cross-tenant-1).
    const acctA = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rt31-acct-A', 'cold', 'active') RETURNING id`,
    );
    await fix.postgres.query(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'cross-tenant-1', 'Iv1.regtest', 'github.com',
                 'medium', 'rt31-A-octo', true, 'active')`,
      [acctA!.id],
    );
    // Pre-seed account B (different account; the attacker target).
    const acctB = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rt31-acct-B', 'cold', 'active') RETURNING id`,
    );

    // Provider returns the IDENTITY's attestation (subject=cross-tenant-1)
    // — but the recovery session targets account B. Models an attacker who
    // controls identity I and tries to use it to recover into a stranger's
    // account.
    const provider2: IdentityProvider = {
      name: 'github_app',
      async beginRegistration(ctx) {
        return { challenge_url: `https://github.com/login/oauth/authorize?state=${ctx.nonce}` };
      },
      async exchangeOrVerify(_input, ctx): Promise<Attestation> {
        return {
          issuer: 'github.com',
          subject: 'cross-tenant-1', // belongs to acctA
          audience: ctx.audience,
          display_handle: 'rt31-A-octo',
          assurance_level: 'medium',
          supports_revalidation: true,
        };
      },
      async revalidate() {
        return { still_valid: true };
      },
    };

    const recoverPubkey = randomBytes(32).toString('base64url');
    const begin = await recoverAccount(
      {
        provider: 'github_app',
        account_id: acctB!.id, // target=B (cross-tenant)
        client_pubkey: recoverPubkey,
      },
      {
        postgres: fix.postgres,
        identity_providers: [provider2],
        redirect_uri: () => 'https://saas.example/callback',
        audience: () => 'Iv1.regtest',
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    const session = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [begin.poll_token],
    );

    const cb = await callback(
      { provider: 'github_app', state: session!.nonce, code: 'gho_stub' },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider2],
        request_context: { ip_hash: Buffer.alloc(32, 9), user_agent: 'integration' },
      },
    );
    expect(cb.status).toBe('failed');
    if (cb.status === 'failed') {
      expect(cb.reason).toBe('identity_account_mismatch');
    }
    // No keys minted into account B from this attempt.
    const keysAtB = await fix.postgres.queryOne<{ c: string }>(
      `SELECT count(*)::text AS c FROM agent_api_keys WHERE account_id = $1`,
      [acctB!.id],
    );
    expect(Number(keysAtB?.c ?? '0')).toBe(0);
  });
});
