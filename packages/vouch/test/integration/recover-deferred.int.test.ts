/**
 * Integration: full SPEC §2.9 owner-approval-gated recovery flow.
 *
 *   1. /recover-account → /begin-registration mints pkr_ session
 *      AND emitOwnerApprovalRequest seeds an agent_recovery_approvals
 *      row with decision='pending'.
 *   2. /callback fires (user did OAuth). The deny-gate sees decision=
 *      'pending', defers issuance: stores awaiting_identity_id on
 *      session, leaves status 'exchanging', NO key issued yet.
 *   3. /recover-account-status returns 'pending' (session is
 *      'exchanging').
 *   4. /recover-account-confirm with decision='approved' finalizes:
 *      issues key on awaiting_identity_id, seals to client_pubkey,
 *      transitions session to 'ready'.
 *   5. /recover-account-status returns 'completed' with sealed payload
 *      that decrypts to a usable bearer.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { recoverAccount } from '../../src/routes/recover-account.js';
import { callback } from '../../src/routes/callback.js';
import { recoverAccountConfirm } from '../../src/routes/recover-account-confirm.js';
import { registrationStatus } from '../../src/routes/registration-status.js';
import {
  sealedBoxReady,
  keypair,
  open as sealedOpen,
} from '../../src/crypto/sealed-box.js';
import {
  emitOwnerApprovalRequest,
  type OwnerApprovalConfig,
} from '../../src/identity/owner-approval-sign.js';
import { signCoSignerEnvelope as _ignored } from '../../src/admin/two-person.js';
import { createHmac, createHash } from 'node:crypto';
import type { Attestation, IdentityProvider } from '../../src/types.js';

const SECRET = Buffer.alloc(32, 0x9c);

class StubProvider implements IdentityProvider {
  readonly name = 'github_app';
  attestation: Attestation = {
    issuer: 'github.com',
    subject: 'sub-deferred-1',
    audience: 'Iv1.deferred',
    display_handle: 'deferred-octocat',
    assurance_level: 'medium',
    supports_revalidation: true,
  };
  async beginRegistration() {
    return { challenge_url: 'https://stub/auth' };
  }
  async exchangeOrVerify() {
    return this.attestation;
  }
  async revalidate() {
    return { still_valid: true };
  }
}

describe('integration: SPEC §2.9 owner-approval-gated recovery (full flow)', () => {
  let fix: IntegrationFixture;
  let provider: StubProvider;
  let agentKp: { publicKey: Buffer; secretKey: Buffer };
  let account_id: string;
  let pollToken: string;

  // Sign helper for the inbound owner-approval webhook (mirrors what
  // a co-signer would compute — the CLI / SaaS UI hands the signature
  // back to /recover-account-confirm).
  function signApprovalRequest(args: {
    method: string;
    path: string;
    body: string;
    nonce: string;
    request_id: string;
    timestamp: number;
  }): string {
    const body_hash = createHash('sha256').update(args.body).digest('hex');
    const canonical = [
      args.method,
      args.path,
      String(args.timestamp),
      args.nonce,
      args.request_id,
      body_hash,
    ].join('\n');
    return createHmac('sha256', SECRET).update(canonical).digest('hex');
  }

  beforeAll(async () => {
    fix = await provisionFixture();
    await sealedBoxReady();
    agentKp = keypair();
    provider = new StubProvider();

    // Seed an account + identity that's been webhook-revoked (Case C
    // re-activation path).
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('deferred-acc', 'cold', 'active') RETURNING id`,
    );
    account_id = acc!.id;
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status, revoked_at, revoked_reason,
          revocation_source)
         VALUES ($1, 'github_app', $2, $3, 'github.com', 'medium',
                 'deferred-octo', true, 'revoked', now(),
                 'user_revoked_app_access', 'webhook') RETURNING id`,
      [account_id, provider.attestation.subject, provider.attestation.audience],
    );
    expect(ident).not.toBeNull();
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('full deferred flow: pending → /callback defers → confirm approved → finalized', async () => {
    // 1. /recover-account.
    const begin = await recoverAccount(
      {
        provider: 'github_app',
        account_id,
        client_pubkey: agentKp.publicKey.toString('base64url'),
      },
      {
        postgres: fix.postgres,
        identity_providers: [provider],
        redirect_uri: () => 'https://saas.test/api/agent-auth/callback/github_app',
        audience: () => provider.attestation.audience,
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'deferred-test' },
      },
    );
    pollToken = begin.poll_token;

    // 2. Seed the owner-approval row directly (the SaaS would normally
    //    call emitOwnerApprovalRequest from /recover-account; we
    //    simulate that side without firing a real outbound webhook).
    const approvalToken = 'aut_' + randomBytes(16).toString('base64url');
    const requestId = randomBytes(16).toString('hex').slice(0, 32);
    await fix.postgres.query(
      `INSERT INTO agent_recovery_approvals
         (request_id, account_id, poll_token, approval_url_token,
          webhook_nonce, webhook_sent_at, decision, expires_at)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5, now(), 'pending', now() + interval '1 hour')`,
      [
        // request_id is UUID; format from raw bytes.
        `${requestId.slice(0, 8)}-${requestId.slice(8, 12)}-${requestId.slice(12, 16)}-${requestId.slice(16, 20)}-${requestId.slice(20, 32)}`,
        account_id,
        pollToken,
        approvalToken,
        randomBytes(32),
      ],
    );

    // 3. Pull the session's nonce so we can run /callback with the
    //    correct state value.
    const sessRow = await fix.postgres.queryOne<{ nonce: string }>(
      `SELECT nonce FROM agent_registration_sessions WHERE poll_token = $1`,
      [pollToken],
    );
    expect(sessRow).not.toBeNull();

    // 4. /callback fires. Pending approval → defer.
    const cb = await callback(
      { provider: 'github_app', state: sessRow!.nonce, code: 'STUB-CODE' },
      {
        postgres: fix.postgres,
        kms: fix.kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'deferred-test' },
      },
    );
    expect(cb.status).toBe('success');

    // 5. Session is in 'exchanging' with awaiting_identity_id set; no
    //    key issued yet.
    const sess1 = await fix.postgres.queryOne<{
      status: string;
      result_ciphertext: Buffer | null;
      awaiting_identity_id: string | null;
    }>(
      `SELECT status::text AS status, result_ciphertext,
              awaiting_identity_id::text AS awaiting_identity_id
         FROM agent_registration_sessions WHERE poll_token = $1`,
      [pollToken],
    );
    expect(sess1?.status).toBe('exchanging');
    expect(sess1?.result_ciphertext).toBeNull();
    expect(sess1?.awaiting_identity_id).toBeTruthy();

    // 6. /recover-account-status returns 'pending'.
    const status1 = await registrationStatus(
      { poll_token: pollToken },
      { postgres: fix.postgres, endpoint: 'recover' },
    );
    expect(status1.status).toBe('pending');

    // 7. /recover-account-confirm with 'approved' → finalize.
    const ts = Math.floor(Date.now() / 1000);
    const body = JSON.stringify({ decision: 'approved' });
    const path = `/api/agent-auth/recover-account-confirm/${approvalToken}`;
    const nonce = 'n-' + randomBytes(16).toString('base64url');
    const reqId = 'r-' + randomBytes(16).toString('hex').slice(0, 16);
    const sig = signApprovalRequest({
      method: 'POST',
      path,
      body,
      nonce,
      request_id: reqId,
      timestamp: ts,
    });

    const confirm = await recoverAccountConfirm(
      {
        approval_url_token: approvalToken,
        path,
        method: 'POST',
        headers: {
          'x-agent-auth-signature': sig,
          'x-agent-auth-timestamp': String(ts),
          'x-agent-auth-nonce': nonce,
          'x-agent-auth-request-id': reqId,
        },
        raw_body: body,
      },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        internal_secret: SECRET,
        kms: fix.kms,
      },
    );
    expect(confirm.decision).toBe('approved');

    // 8. Session is now 'ready' with sealed payload.
    const sess2 = await fix.postgres.queryOne<{
      status: string;
      result_ciphertext: Buffer | null;
      awaiting_identity_id: string | null;
    }>(
      `SELECT status::text AS status, result_ciphertext,
              awaiting_identity_id::text AS awaiting_identity_id
         FROM agent_registration_sessions WHERE poll_token = $1`,
      [pollToken],
    );
    expect(sess2?.status).toBe('ready');
    expect(sess2?.result_ciphertext).not.toBeNull();
    expect(sess2?.awaiting_identity_id).toBeNull();

    // 9. /recover-account-status returns 'completed' with payload.
    const status2 = await registrationStatus(
      { poll_token: pollToken },
      { postgres: fix.postgres, endpoint: 'recover' },
    );
    expect(status2.status).toBe('completed');
    if (status2.status !== 'completed') return;
    expect(status2.encrypted_payload).toBeTruthy();

    // 10. Decrypt + sanity-check the sealed payload.
    const ct = Buffer.from(status2.encrypted_payload!, 'base64url');
    const pt = sealedOpen(ct, agentKp.publicKey, agentKp.secretKey);
    const payload = JSON.parse(pt.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
    };
    expect(payload.key).toMatch(/^agk_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(payload.key_id).toMatch(/^agk_/);
    expect(payload.account_id).toBe(account_id);

    // Suppress unused import in some toolchains.
    void _ignored;
    void emitOwnerApprovalRequest;
    void ({} as OwnerApprovalConfig);
  }, 60_000);
});
