import { describe, it, expect } from 'vitest';
import { createHmac, createHash } from 'node:crypto';
import { verifyInboundOwnerApproval } from '../../src/identity/owner-approval-sign.js';

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
