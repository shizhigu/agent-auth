/**
 * In-database audit writer. SPEC §6.4.1 + §3.8.
 *
 * The 0002 trigger `compute_audit_row_hash` is the source of truth — it
 * sets `prev_hash` and `row_hash` from canonical bytes derived inside
 * Postgres. This module just INSERTs a scrubbed row, and surfaces the
 * row's `id` + `ts` + `row_hash` so callers can mirror it to S3 WORM.
 *
 * Meta is run through the configured scrubber (default §6.6 / RT-44) so
 * the trigger never sees secrets / high-entropy tokens / oversize JSONB.
 */

import { defaultScrubber, type CompiledScrubber } from '../observability/scrubber.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface AuditWriteInput {
  /** event_type taxonomy lives in the lib (e.g. 'key_validated', 'revoke_committed'). */
  readonly event_type: string;
  /** Status class as a small int (2/3/4/5) so we can index by error class. */
  readonly status_class?: 2 | 3 | 4 | 5;
  readonly account_id?: string;
  readonly key_id?: string;
  readonly identity_id?: string;
  readonly endpoint?: string;
  /** HMAC-SHA256(ip, internal_secret) — caller pre-computes. */
  readonly ip_hash?: Buffer;
  readonly asn?: number;
  readonly user_agent?: string;
  /** Cost units (default 1). */
  readonly cost_units?: number;
  /** Free-form meta; will be scrubbed before INSERT. */
  readonly meta?: Record<string, unknown>;
  /** Optional explicit ts override (test-only). Otherwise Postgres `now()`. */
  readonly ts?: Date;
}

export interface AuditWriteResult {
  readonly id: string; // BIGSERIAL → text
  readonly ts: Date;
  readonly row_hash: Buffer;
  readonly prev_hash: Buffer;
}

export interface AuditDbDeps {
  readonly postgres: PostgresAdapter;
  /** Override for tests / cross-cluster audit DBs. Default: defaultScrubber. */
  readonly scrubber?: CompiledScrubber;
}

export async function writeAuditRow(
  input: AuditWriteInput,
  deps: AuditDbDeps,
): Promise<AuditWriteResult> {
  const scrubber = deps.scrubber ?? defaultScrubber;
  const meta_scrubbed =
    input.meta !== undefined
      ? (scrubber.scrub(input.meta) as Record<string, unknown>)
      : null;

  const row = await deps.postgres.queryOne<AuditWriteResult>(
    `INSERT INTO agent_audit_log
       (ts, account_id, key_id, identity_id, event_type, endpoint,
        ip_hash, asn, user_agent, status_class, cost_units, meta)
     VALUES (COALESCE($1, now()), $2, $3, $4, $5, $6,
             $7, $8, $9, $10, $11, $12)
     RETURNING id::text AS id, ts, row_hash, prev_hash`,
    [
      input.ts ?? null,
      input.account_id ?? null,
      input.key_id ?? null,
      input.identity_id ?? null,
      input.event_type,
      input.endpoint ?? null,
      input.ip_hash ?? null,
      input.asn ?? null,
      input.user_agent ?? null,
      input.status_class ?? null,
      input.cost_units ?? 1,
      meta_scrubbed !== null ? JSON.stringify(meta_scrubbed) : null,
    ],
  );
  if (!row) throw new Error('audit_insert_returned_no_row');
  return {
    id: String(row.id),
    ts: row.ts,
    row_hash: Buffer.isBuffer(row.row_hash) ? row.row_hash : Buffer.from(row.row_hash),
    prev_hash: Buffer.isBuffer(row.prev_hash) ? row.prev_hash : Buffer.from(row.prev_hash),
  };
}

/**
 * Lightweight `pseudonymizeIp` helper — SPEC §6.6 listed
 * "ip_address: HMAC-SHA256 with internal_secret" as the storage form.
 * Exposed here so the route layer can compute it once per request and
 * pass to writeAuditRow / metrics labels.
 */
import { createHmac } from 'node:crypto';
export function pseudonymizeIp(ip: string, internal_secret: Buffer): Buffer {
  return createHmac('sha256', internal_secret).update(ip).digest();
}
