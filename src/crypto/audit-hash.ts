/**
 * Audit hash chain canonicalization. Mirrors the SQL trigger
 * `compute_audit_row_hash()` defined in 0002_audit.sql / SPEC §3.8.
 *
 * The trigger is the source of truth in production — this module exists so
 * the offline verifier and tamper-detection job (§6.4.1) can reproduce the
 * chain bit-for-bit without round-tripping Postgres.
 *
 * Canonical form (must match the trigger):
 *
 *   canonical = jsonb_build_object(
 *     'id', id,
 *     'ts', ts,
 *     'event_type', event_type,
 *     'account_id', account_id,
 *     'key_id', key_id,
 *     'endpoint', endpoint,
 *     'status_class', status_class,
 *     'meta_hash', encode(digest(coalesce(meta::text, ''), 'sha256'), 'hex')
 *   )::text
 *
 * row_hash = sha256(prev_hash || canonical_bytes)
 *
 * jsonb_build_object preserves argument order, NOT JSON-spec sorted-key
 * order. The TS implementation here uses the same field order so the
 * resulting bytes match.
 *
 * `meta` is hashed (not embedded) to keep chain hash computation O(1) per
 * row regardless of meta size.
 */

import { createHash } from 'node:crypto';

export interface AuditRow {
  readonly id: number | bigint;
  readonly ts: Date | string;
  readonly event_type: string;
  readonly account_id?: string | null;
  readonly key_id?: string | null;
  readonly endpoint?: string | null;
  readonly status_class?: number | null;
  readonly meta?: unknown;
}

/** Stable JSON encoding of an arbitrary value matching Postgres jsonb::text. */
function encodeJsonbText(v: unknown): string {
  // Approximation: JSON.stringify produces the same bytes as Postgres
  // jsonb::text for the values the lib actually emits (objects with
  // string/number/bool/null leaves; no whitespace; no NaN/Infinity).
  // The trigger's `digest(meta::text, 'sha256')` is taken over the
  // text representation Postgres produces; our verifier replicates by
  // doing the digest in Postgres at verification time when in doubt.
  return JSON.stringify(v);
}

function timestampToText(ts: Date | string): string {
  // Postgres jsonb encodes a timestamptz as ISO 8601 with offset.
  // We use the canonical UTC ISO string — callers must store the same
  // representation everywhere (see SPEC §6.4.1 verifier; it pulls the row's
  // own `ts` column rather than re-deriving, so this only matters for
  // out-of-band canonicalization tests).
  if (typeof ts === 'string') return ts;
  return ts.toISOString();
}

/** Returns the lower-case hex SHA-256 digest of `bytes`. */
export function sha256Hex(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** Returns the SHA-256 digest of `bytes` as raw bytes. */
export function sha256Bytes(bytes: Buffer | string): Buffer {
  return createHash('sha256').update(bytes).digest();
}

/**
 * Build the canonical text used by the trigger. Field order matches
 * jsonb_build_object's call order in 0002_audit.sql.
 */
export function canonicalAuditText(row: AuditRow): string {
  const metaHashHex = sha256Hex(row.meta === undefined ? '' : encodeJsonbText(row.meta));
  // Field order MUST match the SQL trigger.
  const obj: Record<string, unknown> = {
    id: typeof row.id === 'bigint' ? Number(row.id) : row.id,
    ts: timestampToText(row.ts),
    event_type: row.event_type,
    account_id: row.account_id ?? null,
    key_id: row.key_id ?? null,
    endpoint: row.endpoint ?? null,
    status_class: row.status_class ?? null,
    meta_hash: metaHashHex,
  };
  return JSON.stringify(obj);
}

/**
 * row_hash = sha256(prev_hash || canonical_text). Returns 32 bytes.
 */
export function computeRowHash(prev_hash: Buffer, row: AuditRow): Buffer {
  if (prev_hash.length !== 32) {
    throw new Error(`prev_hash_invalid_size: expected 32, got ${prev_hash.length}`);
  }
  const canonical = Buffer.from(canonicalAuditText(row), 'utf8');
  return sha256Bytes(Buffer.concat([prev_hash, canonical]));
}

/** Convenience: 32 zero bytes (the seed prev_hash for the first row of a day). */
export const ZERO_HASH = Buffer.alloc(32, 0);

/**
 * Verify a contiguous chain of rows is intact. Returns the index of the
 * first break (-1 if intact). Caller supplies rows in id-ascending order
 * and the seed prev_hash (ZERO_HASH for the start of a day).
 */
export function verifyChain(
  rows: ReadonlyArray<AuditRow & { prev_hash: Buffer; row_hash: Buffer }>,
  seed_prev_hash: Buffer = ZERO_HASH,
): number {
  let prev = seed_prev_hash;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (!r) return i;
    if (!r.prev_hash.equals(prev)) return i;
    const computed = computeRowHash(prev, r);
    if (!computed.equals(r.row_hash)) return i;
    prev = r.row_hash;
  }
  return -1;
}
