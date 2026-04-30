/**
 * Owner-approval webhook signing + verifying. SPEC §2.9 / RT-19.
 *
 * Outbound: signs and POSTs to the SaaS-configured `approval_webhook_url`
 * a short-lived envelope describing the recovery request. SaaS UI shows
 * the request to the account owner; owner returns approve/deny via a
 * separate URL we build into the webhook body.
 *
 * Inbound (recover-account-confirm): we receive the owner's decision —
 * the same canonical HMAC discipline applies.
 *
 * Canonical signing form (avoids RT-19 forged callbacks):
 *
 *   sig = HMAC-SHA256(
 *     internal_secret,
 *     <method> + "\n" +
 *     <path> + "\n" +
 *     <timestamp> + "\n" +
 *     <nonce> + "\n" +
 *     <request_id> + "\n" +
 *     <sha256(body) hex>
 *   )
 *
 * Headers carry the four metadata fields so the receiver can rebuild
 * the canonical bytes. 5-minute skew tolerance.
 */

import {
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import { AgentAuthError } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { Fetcher } from './github-app/browser-flow.js';

const SKEW_TOLERANCE_MS = 5 * 60 * 1000;

export interface OwnerApprovalConfig {
  /** Where to POST the approval request (SaaS-supplied). */
  readonly approval_webhook_url: string;
  /** 32-byte secret used for HMAC. Usually `config.internal_secret`. */
  readonly internal_secret: Buffer;
  /** Approval URL base; SaaS UI builds the inline confirm URL from this. */
  readonly approval_callback_url_base: string;
  /** Request expiry. Default 24h. */
  readonly request_ttl_seconds?: number;
  /** Injectable HTTP fetch. Defaults to global fetch. */
  readonly fetcher?: Fetcher;
}

export interface OwnerApprovalRequestEnvelope {
  readonly account_id: string;
  readonly poll_token: string;
}

export async function emitOwnerApprovalRequest(
  pg: PostgresAdapter,
  cfg: OwnerApprovalConfig,
  req: OwnerApprovalRequestEnvelope,
): Promise<void> {
  const fetcher = cfg.fetcher ?? fetch;
  const ttl = (cfg.request_ttl_seconds ?? 24 * 3600) * 1000;
  const request_id = randomUuidish();
  const approval_url_token = randomBytes(32).toString('base64url');
  const webhook_nonce = randomBytes(32);
  const expires_at = new Date(Date.now() + ttl);
  const sent_at = new Date();

  await pg.query(
    `INSERT INTO agent_recovery_approvals
       (request_id, account_id, poll_token, approval_url_token,
        webhook_nonce, webhook_sent_at, decision, expires_at)
     VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, 'pending', $7)`,
    [
      request_id,
      req.account_id,
      req.poll_token,
      approval_url_token,
      webhook_nonce,
      sent_at,
      expires_at,
    ],
  );

  const approval_callback_url = `${cfg.approval_callback_url_base}/${approval_url_token}`;
  const body = {
    request_id,
    account_id: req.account_id,
    approval_callback_url,
    expires_at: expires_at.toISOString(),
  };
  const body_str = JSON.stringify(body);
  const headers = signOutbound(
    cfg.internal_secret,
    'POST',
    new URL(cfg.approval_webhook_url).pathname,
    body_str,
    request_id,
    webhook_nonce.toString('base64url'),
  );

  // Best-effort send — the caller can re-poll status; failure does not
  // block /recover-account because the owner can also use the SaaS UI.
  try {
    await fetcher(cfg.approval_webhook_url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      body: body_str,
    });
  } catch {
    // log via SaaS logger in M5; not a correctness gate.
  }
}

interface SignedHeaders {
  'X-Agent-Auth-Signature': string;
  'X-Agent-Auth-Timestamp': string;
  'X-Agent-Auth-Nonce': string;
  'X-Agent-Auth-Request-Id': string;
}

function signOutbound(
  secret: Buffer,
  method: string,
  path: string,
  body: string,
  request_id: string,
  nonce: string,
): SignedHeaders {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const body_hash = createHash('sha256').update(body).digest('hex');
  const canonical = [method, path, timestamp, nonce, request_id, body_hash].join('\n');
  const sig = createHmac('sha256', secret).update(canonical).digest('hex');
  return {
    'X-Agent-Auth-Signature': sig,
    'X-Agent-Auth-Timestamp': timestamp,
    'X-Agent-Auth-Nonce': nonce,
    'X-Agent-Auth-Request-Id': request_id,
  };
}

export interface VerifyInboundInput {
  readonly secret: Buffer;
  readonly method: string;
  readonly path: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly raw_body: Buffer | string;
  readonly now?: () => number;
}

/**
 * Verify an inbound owner-approval callback (RT-19). Throws AgentAuthError
 * on mismatch / skew / replay (caller layer enforces nonce single-use via
 * Redis SET NX EX as documented in §6.2.1 RT-19; this function only checks
 * skew + signature).
 */
export function verifyInboundOwnerApproval(input: VerifyInboundInput): {
  request_id: string;
  nonce: string;
  timestamp: number;
} {
  const sig = lookup(input.headers, 'x-agent-auth-signature');
  const ts = lookup(input.headers, 'x-agent-auth-timestamp');
  const nonce = lookup(input.headers, 'x-agent-auth-nonce');
  const rid = lookup(input.headers, 'x-agent-auth-request-id');
  if (!sig || !ts || !nonce || !rid) {
    throw new AgentAuthError(400, 'invalid_request', 'missing signature headers');
  }
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) {
    throw new AgentAuthError(400, 'invalid_request', 'invalid timestamp');
  }
  const now = (input.now ?? Date.now)();
  if (Math.abs(now - tsNum * 1000) > SKEW_TOLERANCE_MS) {
    throw new AgentAuthError(400, 'invalid_request', 'timestamp skew');
  }
  const body =
    typeof input.raw_body === 'string'
      ? input.raw_body
      : input.raw_body.toString('utf8');
  const body_hash = createHash('sha256').update(body).digest('hex');
  const canonical = [input.method, input.path, ts, nonce, rid, body_hash].join('\n');
  const expected = createHmac('sha256', input.secret).update(canonical).digest('hex');
  if (sig.length !== expected.length) {
    throw new AgentAuthError(401, 'invalid_request', 'invalid signature');
  }
  const ok = timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  if (!ok) {
    throw new AgentAuthError(401, 'invalid_request', 'invalid signature');
  }
  return { request_id: rid, nonce, timestamp: tsNum };
}

function lookup(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string | undefined {
  const lc = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lc) return Array.isArray(v) ? v[0] : v;
  }
  return undefined;
}

function randomUuidish(): string {
  return randomUUID();
}
