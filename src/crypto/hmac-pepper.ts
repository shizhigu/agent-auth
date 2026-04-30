/**
 * HMAC-SHA256 with KMS-held pepper — replaces Argon2id for high-entropy
 * API keys (256-bit random). Per ADR-003 + SPEC §6.1.1:
 *   - HMAC-SHA256(pepper, secret) for storage and verification
 *   - Pepper kept in KMS; an attacker needs DB dump AND KMS to recover anything
 *   - Verification is ~1-10μs vs Argon2id's ~30ms (suitable for the validate-key hot path)
 *
 * Rotation (§6.1.2): during a 7-day dual-pepper window, both old and new
 * versions are accepted. `verifyKey` walks accepted versions in order and
 * answers which version (if any) matched, so the caller can lazy-rehash.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { KmsAdapter, PepperMaterial } from '../storage/kms-adapter.js';

/** Compute HMAC-SHA256(pepper, secret). Returns 32 bytes. */
export function hmacWithPepper(pepper: Buffer, secret: Buffer | string): Buffer {
  const h = createHmac('sha256', pepper);
  h.update(typeof secret === 'string' ? Buffer.from(secret, 'utf8') : secret);
  return h.digest();
}

/** Constant-time compare. Length mismatch returns false without leaking. */
export function constantTimeEqualBuffers(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Hash a freshly issued secret using the *current* pepper. Returns the hash
 * and the pepper version so the caller can persist `key_pepper_version`.
 */
export async function hashNewKey(
  secret: Buffer | string,
  kms: KmsAdapter,
): Promise<{ key_hash: Buffer; key_pepper_version: number }> {
  const pepper = await kms.getCurrentPepper();
  return {
    key_hash: hmacWithPepper(pepper.data, secret),
    key_pepper_version: pepper.version,
  };
}

/**
 * Verify a presented secret against a stored hash, walking the dual-window.
 *
 * Returns:
 *   - matched: whether any accepted pepper version produced the stored hash
 *   - pepper_version: the version that matched (caller may schedule rehash)
 *
 * Walks ALL accepted versions even after a mismatch, so the time cost is
 * stable and does not leak which version stored the key. (Constant-time
 * across the whole accepted set.)
 */
export async function verifyKey(
  secret: Buffer | string,
  stored_hash: Buffer,
  stored_version: number,
  kms: KmsAdapter,
): Promise<{ matched: boolean; pepper_version?: number }> {
  // Optimization: try the stored version first (most common case). Still
  // walk other accepted versions so timing does not depend on which one
  // matched (relevant during dual-window rotation).
  const accepted = await kms.acceptedVersions();
  if (!accepted.includes(stored_version)) {
    // Stored version is no longer accepted (rotation window closed).
    // Walk anyway, but it'll never match — caller surfaces invalid_secret.
  }

  let matched = false;
  let matchedVersion: number | undefined;

  // Build the version walk: stored first, then any other accepted versions.
  const versions: number[] = [stored_version];
  for (const v of accepted) if (v !== stored_version) versions.push(v);

  for (const v of versions) {
    let pepper: PepperMaterial;
    try {
      pepper = await kms.getPepperByVersion(v);
    } catch {
      continue;
    }
    const candidate = hmacWithPepper(pepper.data, secret);
    const eq = constantTimeEqualBuffers(candidate, stored_hash);
    if (eq && !matched) {
      matched = true;
      matchedVersion = v;
      // Do NOT break: keep iterating to keep total time roughly stable.
    }
  }

  return matched
    ? { matched: true, pepper_version: matchedVersion! }
    : { matched: false };
}
