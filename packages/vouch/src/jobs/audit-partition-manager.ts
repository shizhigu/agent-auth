/**
 * Daily audit-log partition manager. SPEC §3.8 + §13.1.2.
 *
 * Pre-creates daily partitions of `agent_audit_log` for the next N days
 * so writes never land in `agent_audit_log_default` (the catch-all).
 * Without these partitions, BRIN indexes can't prune by ts and detach-
 * for-archive is impossible.
 *
 * Idempotent: re-running on the same day skips partitions that already
 * exist. Names are deterministic (`agent_audit_log_YYYY_MM_DD`) so
 * external retention tooling (and RB-6) can target them by date.
 *
 * The job is meant to run daily (e.g. 23:50 UTC) but the implementation
 * is tolerant of missed runs — passing `lookahead_days = 7` gives a
 * week-long buffer.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface AuditPartitionManagerDeps {
  /** Admin-role adapter — partition creation requires CREATE on the schema. */
  readonly postgres: PostgresAdapter;
  /** Number of days ahead to pre-create. Default 7. */
  readonly lookahead_days?: number;
  /** Now for tests. */
  readonly now?: () => Date;
  /** Hook for SREs: called once per partition created (label, meta). */
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface AuditPartitionManagerResult {
  readonly created: ReadonlyArray<string>;
  readonly skipped: ReadonlyArray<string>;
}

export async function manageAuditPartitions(
  deps: AuditPartitionManagerDeps,
): Promise<AuditPartitionManagerResult> {
  const lookahead = deps.lookahead_days ?? 7;
  if (lookahead < 1 || lookahead > 90) {
    throw new Error('lookahead_days must be in [1, 90]');
  }
  const now = deps.now ? deps.now() : new Date();
  const created: string[] = [];
  const skipped: string[] = [];

  for (let i = 0; i < lookahead; i++) {
    const day = addDaysUtc(now, i);
    const next = addDaysUtc(day, 1);
    const name = partitionName(day);
    // Use full UTC timestamptz literals — the parent column is TIMESTAMPTZ
    // so date-only literals would be cast at the session timezone (which
    // may not be UTC), shifting partition boundaries unpredictably.
    const fromTs = `${isoDate(day)} 00:00:00+00`;
    const toTs = `${isoDate(next)} 00:00:00+00`;

    try {
      const exists = await deps.postgres.queryOne<{ regclass: string | null }>(
        `SELECT to_regclass($1)::text AS regclass`,
        [name],
      );
      if (exists?.regclass) {
        skipped.push(name);
        continue;
      }
      // PG forbids bind parameters in FOR VALUES expressions: bound
      // expressions must be literal at parse time. We safely inline
      // the timestamps because they are constructed deterministically
      // from a Date (no user input on the path) and the format matches
      // a strict regex check below.
      const fromLit = quoteTimestampLiteral(fromTs);
      const toLit = quoteTimestampLiteral(toTs);
      await deps.postgres.query(
        `CREATE TABLE ${quoteIdent(name)}
           PARTITION OF agent_audit_log
           FOR VALUES FROM (${fromLit}) TO (${toLit})`,
      );
      created.push(name);
      deps.onAlert?.('audit_partition_created', { name, from: fromTs, to: toTs });
    } catch (err) {
      // Surface the failure without breaking the loop — operators see all
      // missing days at once. The default partition still catches writes.
      deps.onAlert?.('audit_partition_create_failed', {
        name,
        error: errorMessage(err),
      });
    }
  }
  return { created, skipped };
}

function addDaysUtc(d: Date, days: number): Date {
  const out = new Date(d);
  out.setUTCHours(0, 0, 0, 0);
  out.setUTCDate(out.getUTCDate() + days);
  return out;
}

function isoDate(d: Date): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

function partitionName(d: Date): string {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, '0');
  const day = String(d.getUTCDate()).padStart(2, '0');
  return `agent_audit_log_${y}_${m}_${day}`;
}

const IDENT_RE = /^[a-z_][a-z0-9_]*$/;
function quoteIdent(name: string): string {
  // Defense in depth: the name is computed from a Date so this should
  // always pass — but if a future caller injects something, we refuse.
  if (!IDENT_RE.test(name)) {
    throw new Error(`unsafe_partition_name: ${name}`);
  }
  return name;
}

const TS_RE = /^\d{4}-\d{2}-\d{2} 00:00:00\+00$/;
function quoteTimestampLiteral(ts: string): string {
  // Strict: only the exact YYYY-MM-DD 00:00:00+00 form we generate.
  if (!TS_RE.test(ts)) {
    throw new Error(`unsafe_partition_bound: ${ts}`);
  }
  return `TIMESTAMP WITH TIME ZONE '${ts}'`;
}

function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return 'unknown_error';
}
