/**
 * Idempotency reconciliation observer. SPEC §5.1.2.
 *
 * Runs every 60 s. For rows in `pending` or `unknown` older than 5 minutes:
 *   1. If reconcile_attempts ≥ 5 OR last_reconcile_at older than 30 min ago,
 *      promote to `manual_required` and page on-call.
 *   2. Otherwise, look up the resource state by `resource_ref` and compare
 *      to the operation's expected committed shape:
 *        - 'committed':   move to 'completed' (with cached outcome).
 *        - 'not_found':   move to 'failed' (commit lost / never landed).
 *        - 'indeterminate': bump reconcile_attempts; try again next pass.
 *
 * The trigger in 0004_idempotency.sql enforces transition legality. Admin
 * overrides require role `agent_auth_admin` and are logged automatically.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface ReconcileObserverDeps {
  readonly postgres: PostgresAdapter;
  /** Page hook: invoked when a row promotes to manual_required. */
  readonly pageOncall?: (label: string, meta: Record<string, unknown>) => void;
  /** Inspect the actual resource state for a given (operation_type, resource_ref). */
  readonly checkResourceState: (
    operation_type: string,
    resource_ref: string,
  ) => Promise<ResourceState>;
}

export type ResourceState =
  | { kind: 'committed'; outcome_status: number; outcome_body: unknown }
  | { kind: 'not_found' }
  | { kind: 'indeterminate' };

export interface ReconcileResult {
  readonly inspected: number;
  readonly promoted_completed: number;
  readonly promoted_failed: number;
  readonly promoted_manual_required: number;
}

interface StaleRow {
  key: string;
  operation_type: string;
  resource_ref: string;
  reconcile_attempts: number;
  last_reconcile_at: Date | null;
}

const MAX_ATTEMPTS = 5;
const MAX_AGE_MS = 30 * 60 * 1000; // 30 min
const STALE_AFTER_MS = 5 * 60 * 1000;

export async function reconcileUnknownIdempotency(
  deps: ReconcileObserverDeps,
  now: Date = new Date(),
): Promise<ReconcileResult> {
  const cutoff = new Date(now.getTime() - STALE_AFTER_MS);
  const stale = await deps.postgres.query<StaleRow>(
    `SELECT key, operation_type, resource_ref, reconcile_attempts, last_reconcile_at
       FROM agent_idempotency
      WHERE state IN ('pending', 'unknown')
        AND created_at < $1
      ORDER BY created_at ASC
      LIMIT 100`,
    [cutoff],
  );

  let inspected = 0;
  let promoted_completed = 0;
  let promoted_failed = 0;
  let promoted_manual_required = 0;

  for (const row of stale.rows) {
    inspected++;
    const tooManyAttempts = row.reconcile_attempts >= MAX_ATTEMPTS;
    const tooOld =
      row.last_reconcile_at !== null &&
      now.getTime() - row.last_reconcile_at.getTime() > MAX_AGE_MS;

    if (tooManyAttempts || tooOld) {
      await deps.postgres.query(
        `UPDATE agent_idempotency
            SET state = 'manual_required', manual_required_at = now()
          WHERE key = $1 AND state IN ('pending', 'unknown')`,
        [row.key],
      );
      promoted_manual_required++;
      deps.pageOncall?.('idempotency_manual_required', {
        key: row.key,
        operation_type: row.operation_type,
        resource_ref: row.resource_ref,
      });
      continue;
    }

    let actual: ResourceState;
    try {
      actual = await deps.checkResourceState(row.operation_type, row.resource_ref);
    } catch {
      actual = { kind: 'indeterminate' };
    }

    await deps.postgres.query(
      `UPDATE agent_idempotency
          SET reconcile_attempts = reconcile_attempts + 1,
              last_reconcile_at = now()
        WHERE key = $1`,
      [row.key],
    );

    if (actual.kind === 'committed') {
      // pending -> completed OR unknown -> completed
      await deps.postgres.query(
        `UPDATE agent_idempotency
            SET state = 'completed',
                outcome_status = $2,
                outcome_body = $3
          WHERE key = $1 AND state IN ('pending', 'unknown')`,
        [row.key, actual.outcome_status, JSON.stringify(actual.outcome_body)],
      );
      promoted_completed++;
    } else if (actual.kind === 'not_found') {
      // SPEC §5.1.2: a stale row whose resource is not_found means the
      // commit lost — both pending AND unknown should flip to failed
      // so retries with the same idempotency key see the cached
      // {code: 'commit_lost'} failure instead of being blocked at 425
      // idempotency_in_flight for the full 25-min cap-out window.
      // The 0004 trigger allows pending -> failed and unknown -> failed.
      await deps.postgres.query(
        `UPDATE agent_idempotency
            SET state = 'failed',
                outcome_status = 500,
                outcome_body = $2
          WHERE key = $1 AND state IN ('pending', 'unknown')`,
        [row.key, JSON.stringify({ error: { code: 'commit_lost' } })],
      );
      promoted_failed++;
    }
    // indeterminate: leave pending/unknown for next pass.
  }

  return {
    inspected,
    promoted_completed,
    promoted_failed,
    promoted_manual_required,
  };
}
