/**
 * Idempotency framework — two-phase reservation. SPEC §5.1.1.
 *
 * Every Tier B mutation requires an Idempotency-Key. The lib reserves a row
 * BEFORE running the actual operation, so concurrent retries with the same
 * key see a deterministic outcome:
 *
 *   - completed: replay the same response (200 / 204).
 *   - failed:    replay the same business error (4xx).
 *   - pending:   another request is in flight; surface 425 idempotency_in_flight.
 *   - unknown:   commit timed out; observer will reconcile (503).
 *   - manual_required: observer gave up; ops must inspect (503).
 *
 * The state machine is enforced by the trigger in 0004_idempotency.sql.
 *
 * `requestHash` is supplied by the caller. Use `canonicalRequestHash()` to
 * derive it from the request body so a retry with a payload mismatch
 * surfaces 409 idempotency_key_payload_mismatch (RT-27).
 */

import { createHash } from 'node:crypto';
import { AgentAuthError, ServiceUnavailableError } from '../errors.js';
import type { AgentAuthErrorCode } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import { TierBTimeoutError, tierBCommit } from '../distributed/tier-b-commit.js';
import type { PoolClient } from 'pg';
import { constantTimeEqualBuffers } from '../crypto/hmac-pepper.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type IdempotencyOperationType =
  | 'revoke'
  | 'rotate_planned'
  | 'rotate_emergency'
  | 'suspend_account'
  | 'close_account'
  | 'erase_account'
  | 'identity_revoke';

export interface IdempotencyResult<T> {
  readonly status: number;
  readonly body: T;
}

export interface IdempotentOperationContext {
  readonly client: PoolClient;
  readonly idempotency_key: string;
  readonly resource_ref: string;
}

export interface TierBIdempotentOptions {
  /** TTL for the idempotency row. Default 24h. */
  readonly ttl_ms?: number;
  /** Tier B commit timeout (forwarded to tierBCommit). */
  readonly timeout_ms?: number;
}

// ---------------------------------------------------------------------------
// canonicalRequestHash
// ---------------------------------------------------------------------------

/**
 * Stable hash of a request payload for the idempotency key match (RT-27).
 *
 * Implementation: deep-sort object keys, JSON.stringify, SHA-256. Arrays
 * preserve order (semantically meaningful in our payloads). Buffers are
 * encoded as base64. Numbers are stringified; null/undefined collapse to
 * null. Date objects become ISO strings.
 */
export function canonicalRequestHash(payload: unknown): Buffer {
  const canonical = canonicalize(payload);
  return createHash('sha256').update(canonical).digest();
}

function canonicalize(v: unknown): string {
  if (v === null || v === undefined) return 'null';
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'bigint') return JSON.stringify(v.toString());
  if (Buffer.isBuffer(v)) return JSON.stringify(v.toString('base64'));
  if (v instanceof Date) return JSON.stringify(v.toISOString());
  if (Array.isArray(v)) return '[' + v.map(canonicalize).join(',') + ']';
  if (typeof v === 'object') {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(JSON.stringify(k) + ':' + canonicalize(obj[k]));
    }
    return '{' + parts.join(',') + '}';
  }
  return 'null';
}

// ---------------------------------------------------------------------------
// tierBIdempotent — phase 1 + 2 (observer is reconcileUnknownIdempotency)
// ---------------------------------------------------------------------------

interface IdempotencyRow {
  key: string;
  request_hash: Buffer;
  operation_type: string;
  resource_ref: string;
  outcome_status: number | null;
  outcome_body: unknown;
  state: 'pending' | 'completed' | 'failed' | 'unknown' | 'manual_required';
  reconcile_attempts: number;
  expires_at: Date;
  created_at: Date;
}

export async function tierBIdempotent<T>(
  pg: PostgresAdapter,
  args: {
    idempotency_key: string;
    request_hash: Buffer;
    operation_type: IdempotencyOperationType;
    resource_ref: string;
  },
  operation: (ctx: IdempotentOperationContext) => Promise<IdempotencyResult<T>>,
  options: TierBIdempotentOptions = {},
): Promise<IdempotencyResult<T>> {
  // ----- Phase 1: durable reservation in a tier-A transaction. -----
  //
  // Race-free: use INSERT ... ON CONFLICT DO NOTHING so concurrent calls
  // with the same idempotency key serialize on the PK lock. The previous
  // pattern (SELECT FOR UPDATE → INSERT) had a TOCTOU window between the
  // two queries — both T1 and T2 would see no row in their SELECT, both
  // would proceed to INSERT, and T2 would hit SQLSTATE 23505 → txn abort
  // → opaque 500 to the caller (the very thing idempotency is supposed
  // to prevent).
  const ttl_ms = options.ttl_ms ?? 24 * 60 * 60 * 1000;
  const reserved = await pg.transaction(async (tx) => {
    const insertRes = await tx.query<{ inserted: boolean }>(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, expires_at)
       VALUES ($1, $2, $3, $4, 'pending', now() + ($5 || ' milliseconds')::interval)
       ON CONFLICT (key) DO NOTHING
       RETURNING (xmax = 0) AS inserted`,
      [
        args.idempotency_key,
        args.request_hash,
        args.operation_type,
        args.resource_ref,
        ttl_ms.toString(),
      ],
    );
    if (insertRes.rows[0]?.inserted === true) {
      // Fresh reservation; proceed to phase 2 with a clean slate.
      return null;
    }
    // Conflict: another caller already reserved this key. Re-fetch the
    // existing row under FOR UPDATE so the replay branch sees a stable
    // snapshot.
    const existing = await tx.query<IdempotencyRow>(
      `SELECT * FROM agent_idempotency WHERE key = $1 FOR UPDATE`,
      [args.idempotency_key],
    );
    return existing.rows[0] ?? null;
  });

  if (reserved) {
    // Replay paths.
    if (
      !constantTimeEqualBuffers(
        Buffer.isBuffer(reserved.request_hash)
          ? reserved.request_hash
          : Buffer.from(reserved.request_hash as ArrayLike<number>),
        args.request_hash,
      )
    ) {
      throw new AgentAuthError(409, 'idempotency_key_payload_mismatch');
    }
    if (reserved.operation_type !== args.operation_type) {
      throw new AgentAuthError(409, 'idempotency_mismatch');
    }
    switch (reserved.state) {
      case 'completed':
        return {
          status: reserved.outcome_status ?? 200,
          body: reserved.outcome_body as T,
        };
      case 'failed': {
        // SPEC §5.1.3: "Retries return same response." Reconstruct the
        // original AgentAuthError from the stored body so the replay's
        // wire shape matches the first call's wire shape (same code,
        // same message, same details), with `replay: true` merged in.
        const stored = (reserved.outcome_body ?? {}) as {
          code?: string;
          message?: string;
          details?: Record<string, unknown>;
        };
        throw new AgentAuthError(
          reserved.outcome_status ?? 500,
          (stored.code ?? 'invalid_request') as AgentAuthErrorCode,
          stored.message,
          { details: { ...(stored.details ?? {}), replay: true } },
        );
      }
      case 'pending':
        throw new AgentAuthError(425, 'idempotency_in_flight', undefined, {
          headers: { 'Retry-After': '1' },
        });
      case 'unknown':
        throw new ServiceUnavailableError('idempotency_unknown_outcome');
      case 'manual_required':
        throw new ServiceUnavailableError('idempotency_manual_required');
    }
  }

  // ----- Phase 2: actual Tier B operation. -----
  let result: IdempotencyResult<T>;
  try {
    result = await tierBCommit(
      () =>
        pg.transaction(async (client) => {
          await client.query("SET LOCAL synchronous_commit = 'remote_apply'");
          const out = await operation({
            client,
            idempotency_key: args.idempotency_key,
            resource_ref: args.resource_ref,
          });
          // Atomic completion: mark the row completed inside the same Tier B
          // transaction so an observer cannot race it.
          await client.query(
            `UPDATE agent_idempotency
                SET state = 'completed',
                    outcome_status = $2,
                    outcome_body = $3
              WHERE key = $1`,
            [args.idempotency_key, out.status, JSON.stringify(out.body)],
          );
          return out;
        }),
      options.timeout_ms !== undefined ? { timeout_ms: options.timeout_ms } : {},
    );
  } catch (err) {
    // tierBCommit converts TierBTimeoutError -> ServiceUnavailableError(durability_unconfirmed)
    // and pg XX098 -> ServiceUnavailableError(durability_unavailable). Either way, the
    // commit might or might not have landed on primary, so mark 'unknown' and let the
    // observer reconcile by resource_ref. We re-throw a 503 with the idempotency-aware
    // code so callers see "retry with same key, observer is on it".
    if (
      err instanceof ServiceUnavailableError &&
      (err.code === 'durability_unconfirmed' || err.code === 'durability_unavailable')
    ) {
      await pg
        .query(
          `UPDATE agent_idempotency SET state = 'unknown' WHERE key = $1 AND state = 'pending'`,
          [args.idempotency_key],
        )
        .catch(() => undefined);
      throw new ServiceUnavailableError('idempotency_unknown_outcome', undefined, {
        cause: err,
      });
    }
    if (err instanceof TierBTimeoutError) {
      // Defensive: if a caller invokes us with the raw timeout (i.e. bypassing
      // tierBCommit), still record unknown and surface 503.
      await pg
        .query(
          `UPDATE agent_idempotency SET state = 'unknown' WHERE key = $1 AND state = 'pending'`,
          [args.idempotency_key],
        )
        .catch(() => undefined);
      throw new ServiceUnavailableError('idempotency_unknown_outcome', undefined, {
        cause: err,
      });
    }
    if (err instanceof AgentAuthError && err.status >= 400 && err.status < 500) {
      // Terminal business failure: persist so retries get the same answer.
      await pg
        .query(
          `UPDATE agent_idempotency
              SET state = 'failed',
                  outcome_status = $2,
                  outcome_body = $3
            WHERE key = $1 AND state = 'pending'`,
          [args.idempotency_key, err.status, JSON.stringify(err.toJSON().error)],
        )
        .catch(() => undefined);
    }
    throw err;
  }

  return result;
}
