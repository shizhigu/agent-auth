/**
 * Audit-outbox flusher. SPEC §6.4.2.
 *
 * Drains `agent_audit_outbox` rows whose WORM PutObject originally failed.
 * Each retry republishes the JSON body to S3 with the same Object Lock
 * COMPLIANCE retention. On success, marks `flushed_at = now()`. On
 * persistent failure, increments `attempts` and surfaces a metric so
 * SREs can investigate before the retention drift becomes audit-worthy.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { WormPutter, AuditWormConfig } from '../audit/worm-writer.js';

export interface OutboxFlusherDeps {
  readonly postgres: PostgresAdapter;
  readonly putter: WormPutter;
  readonly cfg: Pick<AuditWormConfig, 'kms_key_id' | 'retention_years'>;
  /** Max rows per pass; default 100. */
  readonly batch_size?: number;
  /** Max attempts before flagging row for ops. Default 10. */
  readonly max_attempts?: number;
  /** Now. */
  readonly now?: () => Date;
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface OutboxFlushResult {
  readonly inspected: number;
  readonly flushed: number;
  readonly failed: number;
  readonly stuck: number;
}

interface OutboxRow {
  id: string;
  event_id: string;
  /** node-pg returns JSONB columns as parsed JS values. The flusher
   *  re-stringifies for the WORM PutObject body. */
  payload: unknown;
  attempts: number;
  created_at: Date;
}

export async function flushAuditOutbox(
  deps: OutboxFlusherDeps,
): Promise<OutboxFlushResult> {
  const batch_size = deps.batch_size ?? 100;
  const max_attempts = deps.max_attempts ?? 10;

  // Stuck rows (attempts >= max_attempts) MUST be excluded from the working
  // SELECT — otherwise once `batch_size` rows are stuck, they fill every
  // slot of the LIMIT and new outbox writes never get drained. We still
  // surface them for SRE visibility via a separate query below.
  const rows = await deps.postgres.query<OutboxRow>(
    `SELECT id::text AS id, event_id::text AS event_id, payload, attempts, created_at
       FROM agent_audit_outbox
      WHERE flushed_at IS NULL AND attempts < $2
      ORDER BY created_at ASC
      LIMIT $1`,
    [batch_size, max_attempts],
  );

  // Surface stuck rows independently. Capped at 100 per pass so a massive
  // backlog doesn't generate millions of alerts; downstream SRE tooling
  // de-duplicates by event_id.
  const stuck_rows = await deps.postgres.query<{ id: string; event_id: string; attempts: number }>(
    `SELECT id::text AS id, event_id::text AS event_id, attempts
       FROM agent_audit_outbox
      WHERE flushed_at IS NULL AND attempts >= $1
      ORDER BY id ASC
      LIMIT 100`,
    [max_attempts],
  );
  let stuck = 0;
  for (const sr of stuck_rows.rows) {
    stuck++;
    deps.onAlert?.('audit_outbox_stuck', {
      event_id: sr.event_id,
      attempts: sr.attempts,
    });
  }

  let flushed = 0;
  let failed = 0;
  for (const row of rows.rows) {
    // node-pg returns JSONB columns as a parsed object, not a string.
    // String-shaped payloads (legacy / hand-rolled INSERT) are also
    // accepted via JSON.parse fallback.
    let body: { ts: string };
    let bodyJson: string;
    try {
      if (typeof row.payload === 'string') {
        bodyJson = row.payload;
        body = JSON.parse(row.payload) as { ts: string };
      } else if (row.payload && typeof row.payload === 'object') {
        body = row.payload as { ts: string };
        bodyJson = JSON.stringify(row.payload);
      } else {
        throw new Error('payload is neither string nor object');
      }
    } catch {
      // Corrupt payload: bump attempts and continue.
      await deps.postgres
        .query(
          `UPDATE agent_audit_outbox
              SET attempts = attempts + 1, last_error = 'corrupt_payload'
            WHERE id = $1::bigint`,
          [row.id],
        )
        .catch(() => undefined);
      failed++;
      continue;
    }
    const ts = new Date(body.ts);
    const key = `audit/${dateShard(ts)}/${row.event_id}.json`;
    const retainUntil = addYears(deps.now ? deps.now() : new Date(), deps.cfg.retention_years);
    try {
      await deps.putter.putObject({
        Key: key,
        Body: bodyJson,
        ContentType: 'application/json',
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: deps.cfg.kms_key_id,
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: retainUntil,
      });
      await deps.postgres.query(
        `UPDATE agent_audit_outbox
            SET flushed_at = now()
          WHERE id = $1::bigint`,
        [row.id],
      );
      flushed++;
    } catch (err) {
      await deps.postgres
        .query(
          `UPDATE agent_audit_outbox
              SET attempts = attempts + 1,
                  last_error = $2
            WHERE id = $1::bigint`,
          [row.id, errorMessage(err).slice(0, 500)],
        )
        .catch(() => undefined);
      failed++;
    }
  }
  return { inspected: rows.rows.length, flushed, failed, stuck };
}

function dateShard(ts: Date): string {
  const y = ts.getUTCFullYear();
  const m = String(ts.getUTCMonth() + 1).padStart(2, '0');
  const d = String(ts.getUTCDate()).padStart(2, '0');
  return `${y}/${m}/${d}`;
}
function addYears(date: Date, years: number): Date {
  const out = new Date(date);
  out.setUTCFullYear(out.getUTCFullYear() + years);
  return out;
}
function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return 'unknown_error';
}
