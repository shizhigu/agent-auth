/**
 * Reaper for expired auxiliary rows. SPEC §3.14 (recovery_approvals),
 * §5.1.1 (idempotency), §6.4.2 (audit_outbox), §3.15 (agent_jobs).
 *
 * Each table carries its own retention semantic:
 *   - agent_recovery_approvals: any row past expires_at + grace.
 *   - agent_idempotency: only TERMINAL states (completed / failed /
 *     manual_required) past expires_at + grace. The §5.1.2
 *     reconciler still owns 'pending' / 'unknown' rows.
 *   - agent_audit_outbox: rows where flushed_at IS NOT NULL AND
 *     flushed_at < cutoff. WORM is canonical; the outbox row's
 *     purpose is over once the put landed.
 *   - agent_jobs: TERMINAL states (completed / dead) past
 *     completed_at + grace. 'pending' / 'running' rows are owned
 *     by processAgentJobs.
 *
 * Schedule alongside the registration-session reaper (every minute
 * is fine; the relevant indexes keep the SELECTs cheap).
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
  readonly audit_outbox_deleted: number;
  readonly agent_jobs_deleted: number;
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

  // agent_audit_outbox: WORM is canonical post-flush, so any row
  // where flushed_at < cutoff has fulfilled its purpose.
  const outboxRes = await deps.postgres.query(
    `DELETE FROM agent_audit_outbox
       WHERE flushed_at IS NOT NULL AND flushed_at < $1`,
    [cutoff],
  );

  // agent_jobs: terminal-state rows past their completed_at + grace.
  // 'pending' / 'running' rows are owned by processAgentJobs and
  // must NOT be touched.
  const jobsRes = await deps.postgres.query(
    `DELETE FROM agent_jobs
       WHERE status IN ('completed', 'dead')
         AND completed_at IS NOT NULL
         AND completed_at < $1`,
    [cutoff],
  );

  return {
    recovery_approvals_deleted: apprRes.rowCount,
    idempotency_deleted: idemRes.rowCount,
    audit_outbox_deleted: outboxRes.rowCount,
    agent_jobs_deleted: jobsRes.rowCount,
  };
}
