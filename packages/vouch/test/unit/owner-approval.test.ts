import { describe, it, expect } from 'vitest';
import { createHmac, createHash } from 'node:crypto';
import {
  verifyInboundOwnerApproval,
  emitOwnerApprovalRequest,
} from '../../src/identity/owner-approval-sign.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

const SECRET = Buffer.alloc(32, 7);

function signCanonical(
  method: string,
  path: string,
  body: string,
  ts: string,
  nonce: string,
  rid: string,
): string {
  const body_hash = createHash('sha256').update(body).digest('hex');
  const canonical = [method, path, ts, nonce, rid, body_hash].join('\n');
  return createHmac('sha256', SECRET).update(canonical).digest('hex');
}

describe('verifyInboundOwnerApproval (SPEC §2.9 / RT-19)', () => {
  it('accepts a fresh, validly-signed request', () => {
    const body = JSON.stringify({ decision: 'approved' });
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = signCanonical('POST', '/p', body, ts, 'NONCE', 'REQ');
    const out = verifyInboundOwnerApproval({
      secret: SECRET,
      method: 'POST',
      path: '/p',
      headers: {
        'x-agent-auth-signature': sig,
        'x-agent-auth-timestamp': ts,
        'x-agent-auth-nonce': 'NONCE',
        'x-agent-auth-request-id': 'REQ',
      },
      raw_body: body,
    });
    expect(out).toEqual({ request_id: 'REQ', nonce: 'NONCE', timestamp: Number(ts) });
  });

  it('rejects when timestamp is too old (>5 min skew)', () => {
    const body = '{}';
    const ts = String(Math.floor(Date.now() / 1000) - 6 * 60);
    const sig = signCanonical('POST', '/p', body, ts, 'N', 'R');
    expect(() =>
      verifyInboundOwnerApproval({
        secret: SECRET,
        method: 'POST',
        path: '/p',
        headers: {
          'x-agent-auth-signature': sig,
          'x-agent-auth-timestamp': ts,
          'x-agent-auth-nonce': 'N',
          'x-agent-auth-request-id': 'R',
        },
        raw_body: body,
      }),
    ).toThrowError(/skew/);
  });

  it('rejects when signature does not match canonical bytes', () => {
    const body = '{}';
    const ts = String(Math.floor(Date.now() / 1000));
    const sig = signCanonical('GET', '/p', body, ts, 'N', 'R'); // wrong method in canonical
    expect(() =>
      verifyInboundOwnerApproval({
        secret: SECRET,
        method: 'POST',
        path: '/p',
        headers: {
          'x-agent-auth-signature': sig,
          'x-agent-auth-timestamp': ts,
          'x-agent-auth-nonce': 'N',
          'x-agent-auth-request-id': 'R',
        },
        raw_body: body,
      }),
    ).toThrowError(/invalid signature/);
  });

  it('rejects when signature is wrong length (anti-truncation)', () => {
    const ts = String(Math.floor(Date.now() / 1000));
    expect(() =>
      verifyInboundOwnerApproval({
        secret: SECRET,
        method: 'POST',
        path: '/p',
        headers: {
          'x-agent-auth-signature': 'abc',
          'x-agent-auth-timestamp': ts,
          'x-agent-auth-nonce': 'N',
          'x-agent-auth-request-id': 'R',
        },
        raw_body: '{}',
      }),
    ).toThrow();
  });

  it('rejects when any header is missing', () => {
    expect(() =>
      verifyInboundOwnerApproval({
        secret: SECRET,
        method: 'POST',
        path: '/p',
        headers: {
          'x-agent-auth-signature': 'sig',
          'x-agent-auth-timestamp': '0',
        },
        raw_body: '{}',
      }),
    ).toThrowError(/missing signature headers/);
  });
});

describe('emitOwnerApprovalRequest — SPEC §2.5 + §2.9 session TTL extension', () => {
  it('extends agent_registration_sessions.expires_at to match approval window', async () => {
    // Without this, a 5-min session is reaped within 1h (per §2.5
    // reaper grace) — well before the 24h approval window —
    // and the deferred-recovery flow loses its session row.
    const queries: Array<{ text: string; params?: ReadonlyArray<unknown> }> = [];
    const fakePg = {
      async query(text: string, params?: ReadonlyArray<unknown>) {
        queries.push({ text, ...(params !== undefined ? { params } : {}) });
        return { rows: [], rowCount: 0 };
      },
    } as unknown as PostgresAdapter;
    const fakeFetcher: typeof fetch = async () =>
      new Response('', { status: 200 });

    const now_ms = Date.UTC(2027, 0, 1, 12, 0, 0); // fixed instant
    await emitOwnerApprovalRequest(
      fakePg,
      {
        approval_webhook_url: 'https://saas.test/owner-approve',
        internal_secret: SECRET,
        approval_callback_url_base: 'https://saas.test/api/agent-auth/recover-account-confirm',
        request_ttl_seconds: 24 * 3600,
        fetcher: fakeFetcher,
        now: () => now_ms,
      },
      {
        account_id: '00000000-0000-0000-0000-000000000001',
        poll_token: 'pkr_' + 'x'.repeat(43),
      },
    );

    // First query: INSERT into agent_recovery_approvals.
    expect(queries[0]?.text).toMatch(/INSERT INTO agent_recovery_approvals/);
    // Second query: UPDATE the session expires_at to GREATEST(...).
    expect(queries[1]?.text).toMatch(/UPDATE agent_registration_sessions/);
    expect(queries[1]?.text).toMatch(/SET expires_at = GREATEST/);
    // Params: poll_token + the new expires_at (24h from now_ms).
    expect(queries[1]?.params?.[0]).toBe('pkr_' + 'x'.repeat(43));
    const newExpiry = queries[1]?.params?.[1] as Date;
    expect(newExpiry).toBeInstanceOf(Date);
    expect(newExpiry.getTime()).toBe(now_ms + 24 * 3600 * 1000);
  });
});
