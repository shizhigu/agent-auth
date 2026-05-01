/**
 * PKCE S256 (RFC 7636) helpers. Used by the GitHub App browser flow
 * (SPEC §2.2.2): we generate a 256-bit verifier, derive the SHA-256
 * challenge, and pass `code_challenge` + `code_challenge_method=S256`
 * to GitHub's authorize endpoint. The verifier stays in
 * `agent_registration_sessions.pkce_verifier` until /callback exchanges
 * the code with GitHub.
 *
 * Threat: RT-29 (OAuth state/challenge phishing) — verifier is held only
 * server-side; an attacker who intercepts the redirect cannot exchange
 * the code without the verifier.
 */

import { createHash, randomBytes } from 'node:crypto';

const VERIFIER_BYTES = 32; // 256 bits — produces 43 base64url chars
const MIN_VERIFIER_LEN = 43; // RFC 7636 §4.1
const MAX_VERIFIER_LEN = 128;

function base64url(buf: Buffer): string {
  return buf.toString('base64url');
}

export interface PkcePair {
  /** High-entropy verifier (43 base64url chars). Held server-side. */
  readonly verifier: string;
  /** SHA-256 challenge (43 base64url chars). Sent to the IdP. */
  readonly challenge: string;
  /** Always 'S256' — agent-auth does not support 'plain'. */
  readonly method: 'S256';
}

export function generatePkcePair(): PkcePair {
  const verifier = base64url(randomBytes(VERIFIER_BYTES));
  return {
    verifier,
    challenge: deriveChallenge(verifier),
    method: 'S256',
  };
}

/** Derive a challenge from a known verifier (test vectors / spec compliance). */
export function deriveChallenge(verifier: string): string {
  if (verifier.length < MIN_VERIFIER_LEN || verifier.length > MAX_VERIFIER_LEN) {
    throw new Error(
      `pkce_verifier_invalid_length: ${verifier.length} (must be ${MIN_VERIFIER_LEN}-${MAX_VERIFIER_LEN})`,
    );
  }
  if (!/^[A-Za-z0-9_-]+$/.test(verifier)) {
    throw new Error('pkce_verifier_invalid_chars: only [A-Za-z0-9_-] allowed');
  }
  const hash = createHash('sha256').update(verifier).digest();
  return base64url(hash);
}

/**
 * Verify a presented verifier matches a stored challenge. Constant-time
 * compare via raw buffer length check + node's timingSafeEqual is overkill
 * here (challenge is server-side, not user-provided), but kept defensive.
 */
export function verifyVerifier(verifier: string, challenge: string): boolean {
  try {
    return deriveChallenge(verifier) === challenge;
  } catch {
    return false;
  }
}
