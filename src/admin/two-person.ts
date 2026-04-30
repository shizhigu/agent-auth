/**
 * Two-person rule. SPEC §8.1 / RT-10 / RT-41.
 *
 * High-impact admin commands (close-account, flush-cache, migrate-rollback,
 * export-account, force-revoke-all, reset-barrier) require a co-signer
 * approval BEFORE the lib accepts the operation. Co-signer is a separate
 * admin user who signs a canonical envelope:
 *
 *   sig = HMAC-SHA256(internal_secret,
 *           op + "\n" +
 *           target + "\n" +
 *           timestamp + "\n" +
 *           nonce + "\n" +
 *           initiator + "\n" +
 *           sha256(payload) hex)
 *
 * The lib provides:
 *   - createCoSignerEnvelope(): produces the canonical bytes the
 *     co-signer signs. The CLI surfaces this to the human; the human
 *     uses their hardware key (or webauthn.ts) to sign.
 *   - verifyCoSignature(): checks the produced signature against the
 *     canonical envelope, with skew tolerance. Throws AgentAuthError
 *     on any failure.
 *
 * The actual transport (initiator emits the canonical bytes; co-signer
 * pastes the signature back) is the SaaS's choice — the lib only owns
 * the cryptographic discipline.
 */

import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import { AgentAuthError } from '../errors.js';

const SKEW_TOLERANCE_MS = 10 * 60 * 1000; // 10 min — co-signer may need to read

export interface CoSignerEnvelope {
  readonly op: string;
  readonly target: string;
  readonly timestamp: number; // unix seconds
  readonly nonce: string; // base64url 32B
  readonly initiator: string; // initiator admin id
  readonly payload_sha256: string; // hex
  /** The bytes both sides hash. */
  readonly canonical: string;
}

export function createCoSignerEnvelope(args: {
  op: string;
  target: string;
  initiator: string;
  payload: string | Buffer;
  /** Now-ish; injectable for tests. */
  now_ms?: number;
}): CoSignerEnvelope {
  const timestamp = Math.floor((args.now_ms ?? Date.now()) / 1000);
  const nonce = randomBytes(32).toString('base64url');
  const payload_sha256 = createHash('sha256')
    .update(typeof args.payload === 'string' ? args.payload : args.payload)
    .digest('hex');
  const canonical = [
    args.op,
    args.target,
    String(timestamp),
    nonce,
    args.initiator,
    payload_sha256,
  ].join('\n');
  return {
    op: args.op,
    target: args.target,
    timestamp,
    nonce,
    initiator: args.initiator,
    payload_sha256,
    canonical,
  };
}

export function signCoSignerEnvelope(
  envelope: CoSignerEnvelope,
  internal_secret: Buffer,
): string {
  return createHmac('sha256', internal_secret)
    .update(envelope.canonical)
    .digest('hex');
}

export function verifyCoSignature(
  envelope: CoSignerEnvelope,
  signature_hex: string,
  internal_secret: Buffer,
  opts: { now_ms?: number } = {},
): void {
  const now = opts.now_ms ?? Date.now();
  if (Math.abs(now - envelope.timestamp * 1000) > SKEW_TOLERANCE_MS) {
    throw new AgentAuthError(401, 'invalid_request', 'co_signer_timestamp_skew');
  }
  if (!/^[0-9a-f]{64}$/.test(signature_hex)) {
    throw new AgentAuthError(401, 'invalid_request', 'co_signer_signature_malformed');
  }
  const expected = signCoSignerEnvelope(envelope, internal_secret);
  const ok = timingSafeEqual(
    Buffer.from(expected, 'hex'),
    Buffer.from(signature_hex, 'hex'),
  );
  if (!ok) {
    throw new AgentAuthError(401, 'invalid_request', 'co_signer_signature_mismatch');
  }
}

/** Test-only helper to keep deterministic envelopes. */
export function rebuildEnvelopeFromParts(parts: {
  op: string;
  target: string;
  timestamp: number;
  nonce: string;
  initiator: string;
  payload_sha256: string;
}): CoSignerEnvelope {
  const canonical = [
    parts.op,
    parts.target,
    String(parts.timestamp),
    parts.nonce,
    parts.initiator,
    parts.payload_sha256,
  ].join('\n');
  return { ...parts, canonical };
}
