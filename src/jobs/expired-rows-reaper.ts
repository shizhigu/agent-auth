/**
 * Reaper for expired auxiliary rows. SPEC §3.14 (recovery_approvals)
 * + §5.1.1 (idempotency).
 *
 * Both tables carry their own `expires_at` (24h default). Without a
 * reaper rows accumulate forever — neither is consulted post-expiry,
 * but the indexes grow and `count(*)` queries get slower over time.
 *
 * Conservative: we only delete rows that are well past their expiry
 * AND in a TERMINAL state, so any in-flight idempotency reservation
 * the §5.1.2 reconciler is still working on isn't stomped on.
 *
 * Schedule it alongside the registration-session reaper (every minute
 * is fine; the `expires_at` index keeps the SELECT cheap).
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface ExpiredRowsReaperDeps {
  readonly postgres: PostgresAdapter;
  /** Grace period after expires_at before deletion. Default 1 h —
   *  matches the agent_registration_sessions reaper grace. */
  readonly grace_ms?: number;
  readonly now?: () => Date;
}

export interface ExpiredRowsReaperResult {
  readonly recovery_approvals_deleted: number;
  readonly idempotency_deleted: number;
}

const DEFAULT_GRACE_MS = 60 * 60 * 1000;

export async function reapExpiredRows(
  deps: ExpiredRowsReaperDeps,
): Promise<ExpiredRowsReaperResult> {
  const grace = deps.grace_ms ?? DEFAULT_GRACE_MS;
  const now = deps.now ? deps.now() : new Date();
  const cutoff = new Date(now.getTime() - grace);

  // agent_recovery_approvals: any decision (approved/denied/pending)
  // older than `cutoff` is dead. The pending ones older than 24h+1h
  // are abandoned by the agent SDK, so dropping them is safe.
  const apprRes = await deps.postgres.query(
    `DELETE FROM agent_recovery_approvals
       WHERE expires_at < $1`,
    [cutoff],
  );

  // agent_idempotency: only reap rows in a terminal state. The §5.1.2
  // reconciler still owns 'pending' / 'unknown' rows even past
  // expires_at — it'll promote them to 'manual_required' first; THAT
  // becomes the terminal state. 'manual_required' is reaped here too
  // because it's terminal — operator inspection happens via the
  // resolve-idempotency runbook, not by row preservation.
  const idemRes = await deps.postgres.query(
    `DELETE FROM agent_idempotency
       WHERE expires_at < $1
         AND state IN ('completed', 'failed', 'manual_required')`,
    [cutoff],
  );

  return {
    recovery_approvals_deleted: apprRes.rowCount,
    idempotency_deleted: idemRes.rowCount,
  };
}
