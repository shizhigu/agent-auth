/**
 * Integration: /recover-account-confirm against real Postgres + Redis.
 * SPEC §2.9 / RT-19 / RT-41.
 *
 * Verifies:
 *   - owner approve persists to agent_recovery_approvals (decision='approved').
 *   - replay with the SAME nonce is rejected (Redis SET NX guard).
 *   - skew > 5 min is rejected (canonical timestamp window).
 *   - decision is idempotent: re-call with a different nonce + correct sig
 *     returns the original decision (the 0003 trigger has no transition
 *     enforcement, but the route's "already decided" branch returns the
 *     cached row instead of overwriting).
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import {
  recoverAccountConfirm,
  type RecoverAccountConfirmInput,
} from '../../src/routes/recover-account-confirm.js';

const SECRET = Buffer.alloc(32, 0xab);
const PATH = '/api/agent-auth/recover-account-confirm/abc';

function sign(
  body: string,
  ts: string,
  nonce: string,
  request_id: string,
): string {
  const body_hash = createHash('sha256').update(body).digest('hex');
  const canonical = ['POST', PATH, ts, nonce, request_id, body_hash].join('\n');
  return createHmac('sha256', SECRET).update(canonical).digest('hex');
}

function input(args: {
  approval_url_token: string;
  body: string;
  ts: string;
  nonce: string;
  request_id: string;
}): RecoverAccountConfirmInput {
  return {
    approval_url_token: args.approval_url_token,
    method: 'POST',
    path: PATH,
    headers: {
      'x-agent-auth-signature': sign(args.body, args.ts, args.nonce, args.request_id),
      'x-agent-auth-timestamp': args.ts,
      'x-agent-auth-nonce': args.nonce,
      'x-agent-auth-request-id': args.request_id,
    },
    raw_body: args.body,
  };
}

describe('integration: /recover-account-confirm (SPEC §2.9 / RT-19)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  async function plantApprovalRow(
    approval_url_token: string,
  ): Promise<{ request_id: string; account_id: string }> {
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rec-confirm', 'cold', 'active') RETURNING id`,
    );
    const request_id = randomUUID();
    await fix.postgres.query(
      `INSERT INTO agent_recovery_approvals
         (request_id, account_id, poll_token, approval_url_token,
          webhook_nonce, webhook_sent_at, decision, expires_at)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5, now(), 'pending', now() + interval '1 hour')`,
      [
        request_id,
        acc!.id,
        'pkr_' + randomBytes(32).toString('base64url'),
        approval_url_token,
        randomBytes(32),
      ],
    );
    return { request_id, account_id: acc!.id };
  }

  beforeEach(async () => {
    // Clear Redis nonce keys between tests so replays are deterministic.
    await fix.redis_client.flushdb();
  });

  it('approve persists decision and request_id to the agent_recovery_approvals row', async () => {
    const token = 'tok_' + randomBytes(16).toString('base64url');
    const planted = await plantApprovalRow(token);
    const ts = String(Math.floor(Date.now() / 1000));
    const body = JSON.stringify({ decision: 'approved' });
    const out = await recoverAccountConfirm(
      input({
        approval_url_token: token,
        body,
        ts,
        nonce: 'N1',
        request_id: 'R1',
      }),
      {
        postgres: fix.postgres,
        redis: fix.redis,
        internal_secret: SECRET,
      },
    );
    expect(out.decision).toBe('approved');
    expect(out.account_id).toBe(planted.account_id);

    const row = await fix.postgres.queryOne<{
      decision: string;
      decision_at: Date | null;
    }>(
      `SELECT decision, decision_at FROM agent_recovery_approvals
        WHERE approval_url_token = $1`,
      [token],
    );
    expect(row?.decision).toBe('approved');
    expect(row?.decision_at).not.toBeNull();

    // SPEC §6.4 — owner-decision audit row written in-tx.
    const audit = await fix.postgres.queryOne<{ event_type: string }>(
      `SELECT event_type FROM agent_audit_log
        WHERE event_type = 'recover_account_owner_decision'
          AND account_id = $1::uuid
        ORDER BY id DESC LIMIT 1`,
      [planted.account_id],
    );
    expect(audit?.event_type).toBe('recover_account_owner_decision');
  });

  it('replay with same nonce is rejected (RT-19 single-use guard via Redis SET NX)', async () => {
    const token = 'tok_' + randomBytes(16).toString('base64url');
    await plantApprovalRow(token);
    const ts = String(Math.floor(Date.now() / 1000));
    const body = JSON.stringify({ decision: 'approved' });
    const inp = input({
      approval_url_token: token,
      body,
      ts,
      nonce: 'NONCE_REPLAY',
      request_id: 'R',
    });
    const deps = {
      postgres: fix.postgres,
      redis: fix.redis,
      internal_secret: SECRET,
    };
    await recoverAccountConfirm(inp, deps);
    await expect(recoverAccountConfirm(inp, deps)).rejects.toMatchObject({
      status: 401,
    });
  });

  it('timestamp > 5 min skew is rejected', async () => {
    const token = 'tok_' + randomBytes(16).toString('base64url');
    await plantApprovalRow(token);
    const ts = String(Math.floor(Date.now() / 1000) - 6 * 60); // 6 min in the past
    const body = JSON.stringify({ decision: 'denied', reason: 'ts-skew' });
    await expect(
      recoverAccountConfirm(
        input({
          approval_url_token: token,
          body,
          ts,
          nonce: 'NONCE_SKEW',
          request_id: 'R',
        }),
        {
          postgres: fix.postgres,
          redis: fix.redis,
          internal_secret: SECRET,
        },
      ),
    ).rejects.toThrowError(/skew/);
  });

  it('idempotent decision: a fresh nonce against an already-decided row returns the cached decision', async () => {
    const token = 'tok_' + randomBytes(16).toString('base64url');
    await plantApprovalRow(token);
    const deps = {
      postgres: fix.postgres,
      redis: fix.redis,
      internal_secret: SECRET,
    };
    const first = await recoverAccountConfirm(
      input({
        approval_url_token: token,
        body: JSON.stringify({ decision: 'denied', reason: 'first' }),
        ts: String(Math.floor(Date.now() / 1000)),
        nonce: 'NONCE_FIRST',
        request_id: 'R',
      }),
      deps,
    );
    expect(first.decision).toBe('denied');
    // Try again with a fresh nonce + a different body — the route's
    // "already decided" branch returns the cached decision unchanged.
    const second = await recoverAccountConfirm(
      input({
        approval_url_token: token,
        body: JSON.stringify({ decision: 'approved', reason: 'second' }),
        ts: String(Math.floor(Date.now() / 1000)),
        nonce: 'NONCE_SECOND',
        request_id: 'R',
      }),
      deps,
    );
    expect(second.decision).toBe('denied'); // SAME as first
    expect(second.request_id).toBe(first.request_id);
  });
});
