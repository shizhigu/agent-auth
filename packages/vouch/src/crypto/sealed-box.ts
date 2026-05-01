/**
 * Sealed-box delivery (X25519 + XSalsa20-Poly1305) via libsodium's
 * `crypto_box_seal`. Per ADR-004 / SPEC §2.6:
 *
 *   - Anonymous sender: only the agent's private key (held client-side,
 *     committed to at /begin-registration via client_pubkey) can decrypt
 *     the payload returned from /registration-status.
 *   - 48 bytes of overhead (32-byte ephemeral pubkey + 16-byte MAC).
 *   - Forward secrecy across sessions: a future internal_secret leak does
 *     NOT compromise past sealed-box payloads.
 *
 * Threats mitigated: RT-20 (pubkey substitution — client_pubkey is bound
 * to the poll_token at /begin-registration; immutable thereafter).
 *
 * libsodium is async-init: callers must `await sealedBoxReady()` once at
 * process start. The seal/open helpers throw if called pre-init so the
 * SaaS sees a deterministic error rather than a confusing buffer error.
 */

import sodium from 'libsodium-wrappers';

let initialized = false;

/** Ensure libsodium is ready. Must be awaited once at process start. */
export async function sealedBoxReady(): Promise<void> {
  if (initialized) return;
  await sodium.ready;
  initialized = true;
}

function ensureReady(): void {
  if (!initialized) {
    throw new Error('sealed_box_not_initialized: call sealedBoxReady() first');
  }
}

export const SEALED_BOX_PUBKEY_BYTES = 32;
/** crypto_box_seal overhead = 48 (ephemeral pubkey + MAC). */
export const SEALED_BOX_OVERHEAD = 48;

/**
 * Seal `plaintext` to the agent's `recipient_pubkey`. Returns ciphertext.
 *
 * The plaintext is exactly the §2.6 JSON object (already serialized).
 */
export function seal(plaintext: Buffer | string, recipient_pubkey: Buffer): Buffer {
  ensureReady();
  if (recipient_pubkey.length !== SEALED_BOX_PUBKEY_BYTES) {
    throw new Error(
      `sealed_box_pubkey_invalid_size: expected ${SEALED_BOX_PUBKEY_BYTES}, got ${recipient_pubkey.length}`,
    );
  }
  const pt =
    typeof plaintext === 'string'
      ? Buffer.from(plaintext, 'utf8')
      : plaintext;
  const ct = sodium.crypto_box_seal(pt, recipient_pubkey);
  return Buffer.from(ct);
}

/**
 * Open a sealed-box ciphertext using the recipient keypair. Used by the
 * agent SDK; the lib itself does not decrypt anything (the SaaS server
 * has no decryption key — by design).
 *
 * Lives here so unit tests can round-trip the format without depending
 * on the SDK package.
 */
export function open(
  ciphertext: Buffer,
  recipient_pubkey: Buffer,
  recipient_secret: Buffer,
): Buffer {
  ensureReady();
  if (recipient_pubkey.length !== SEALED_BOX_PUBKEY_BYTES) {
    throw new Error('sealed_box_pubkey_invalid_size');
  }
  if (recipient_secret.length !== SEALED_BOX_PUBKEY_BYTES) {
    throw new Error('sealed_box_secret_invalid_size');
  }
  const pt = sodium.crypto_box_seal_open(
    ciphertext,
    recipient_pubkey,
    recipient_secret,
  );
  if (!pt) throw new Error('sealed_box_decrypt_failed');
  return Buffer.from(pt);
}

/** Generate a fresh sealed-box keypair (test + agent-SDK helper). */
export function keypair(): { publicKey: Buffer; secretKey: Buffer } {
  ensureReady();
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: Buffer.from(kp.publicKey),
    secretKey: Buffer.from(kp.privateKey),
  };
}
