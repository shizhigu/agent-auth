/**
 * Audit hash-chain verifier. SPEC §6.4.1.
 *
 * Hourly job that re-reads today's audit_log rows in id-ascending order
 * and walks the hash chain via `verifyChain` (src/crypto/audit-hash.ts).
 * Any break is paged via `onAlert` — the §6.4.1 runbook is the response
 * procedure (RB-6 audit log tamper response).
 *
 * The job intentionally does NOT cross daily partitions: each partition
 * starts a fresh chain seeded with ZERO_HASH, matching the §3.8 trigger.
 */

import { verifyChain, ZERO_HASH } from '../crypto/audit-hash.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface AuditVerifierDeps {
  readonly postgres: PostgresAdapter;
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
  /** Override 'now' for tests. */
  readonly now?: () => Date;
  /**
   * Optional explicit UTC day to verify. When set, the verifier scopes
   * its read to `[target_day, target_day + 1 day)` instead of the
   * default `today only`. Use case: RB-6 forensic response — verify a
   * specific suspect day after a tamper alert.
   */
  readonly target_day?: Date;
}

export interface AuditVerifierResult {
  readonly inspected: number;
  /** -1 = intact; otherwise index of first break. */
  readonly first_break_index: number;
  readonly first_break_id?: string;
  /** ts in ISO of the first broken row, when available. */
  readonly first_break_ts?: string;
}

interface AuditRowDB {
  id: string;
  ts: Date;
  event_type: string;
  account_id: string | null;
  key_id: string | null;
  endpoint: string | null;
  status_class: number | null;
  meta: unknown;
  prev_hash: Buffer;
  row_hash: Buffer;
}

export async function verifyAuditChain(
  deps: AuditVerifierDeps,
): Promise<AuditVerifierResult> {
  const now = deps.now ? deps.now() : new Date();
  const day_anchor = deps.target_day ?? now;
  const day_start = new Date(
    Date.UTC(
      day_anchor.getUTCFullYear(),
      day_anchor.getUTCMonth(),
      day_anchor.getUTCDate(),
    ),
  );
  const day_end = new Date(day_start.getTime() + 24 * 60 * 60 * 1000);
  // When verifying a historical day, scope the read with an upper bound so
  // we don't accidentally splice in rows from later days (which would have
  // their own ZERO_HASH-seeded chain). Today-only mode also benefits from
  // the bound — late writers can't alter the inspected window mid-run.
  const rows = await deps.postgres.query<AuditRowDB>(
    `SELECT id::text AS id, ts, event_type, account_id::text AS account_id,
            key_id, endpoint, status_class, meta, prev_hash, row_hash
       FROM agent_audit_log
      WHERE ts >= $1 AND ts < $2
      ORDER BY id ASC`,
    [day_start, day_end],
  );

  const built = rows.rows.map((r) => ({
    id: Number(r.id),
    ts: r.ts,
    event_type: r.event_type,
    account_id: r.account_id,
    key_id: r.key_id,
    endpoint: r.endpoint,
    status_class: r.status_class,
    meta: r.meta,
    prev_hash: Buffer.isBuffer(r.prev_hash) ? r.prev_hash : Buffer.from(r.prev_hash),
    row_hash: Buffer.isBuffer(r.row_hash) ? r.row_hash : Buffer.from(r.row_hash),
  }));
  const breakIdx = verifyChain(built, ZERO_HASH);
  if (breakIdx >= 0) {
    const first = rows.rows[breakIdx];
    deps.onAlert?.('audit_hash_chain_break', {
      at_id: first?.id ?? null,
      ts: first?.ts.toISOString() ?? null,
      partition_start: day_start.toISOString(),
    });
    return {
      inspected: rows.rows.length,
      first_break_index: breakIdx,
      ...(first ? { first_break_id: first.id, first_break_ts: first.ts.toISOString() } : {}),
    };
  }
  return { inspected: rows.rows.length, first_break_index: -1 };
}
