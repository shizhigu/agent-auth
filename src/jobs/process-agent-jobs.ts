/**
 * Generic worker for the `agent_jobs` queue. SPEC §3.15.
 *
 * v0.1 only emits one kind of job: 'cache_invalidate_keys' (enqueued by
 * the `sync_account_tier_to_keys` trigger when an account's tier
 * changes). Other kinds are accepted and acked as no-ops so a future
 * SaaS that adds custom kinds can register them via `extra_handlers`.
 *
 * Concurrency model:
 *   - SELECT FOR UPDATE SKIP LOCKED inside a tier-A transaction picks
 *     the oldest runnable job and pins it to this worker.
 *   - The handler runs OUTSIDE the locking transaction (so a slow
 *     handler does not block the row lock for long; the
 *     `agent_jobs_stuck` index lets ops see jobs whose worker died).
 *   - On success: status='completed', completed_at=now().
 *   - On failure: attempts++, status back to 'pending' (or 'dead' if
 *     attempts >= max_attempts).
 *
 * Idempotency: cache_invalidate_keys is naturally idempotent — calling
 * `invalidateKey` twice for the same key_id has no extra effect. Other
 * kinds must guarantee their own idempotency.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import { invalidateKey } from '../distributed/cache-invalidation.js';

export type AgentJobKind = 'cache_invalidate_keys' | string;

export interface AgentJobRow {
  readonly id: string;
  readonly kind: AgentJobKind;
  readonly payload: Record<string, unknown>;
  readonly attempts: number;
  readonly max_attempts: number;
}

export interface ProcessAgentJobsDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  /** Worker identity for `locked_by` (e.g. hostname/pid). */
  readonly worker_id?: string;
  /** Max jobs per pass. Default 100. */
  readonly batch_size?: number;
  /** Custom handlers keyed by `kind`. Override built-in or extend. */
  readonly extra_handlers?: Readonly<Record<string, JobHandler>>;
  /** Now for tests. */
  readonly now?: () => Date;
  /** Optional alert hook for stuck / dead-lettered jobs. */
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface JobHandler {
  (
    payload: Record<string, unknown>,
    deps: { postgres: PostgresAdapter; redis: RedisAdapter },
  ): Promise<void>;
}

export interface ProcessAgentJobsResult {
  readonly inspected: number;
  readonly completed: number;
  readonly failed: number;
  readonly dead: number;
}

const DEFAULT_BATCH = 100;

export async function processAgentJobs(
  deps: ProcessAgentJobsDeps,
): Promise<ProcessAgentJobsResult> {
  const batch = deps.batch_size ?? DEFAULT_BATCH;
  const worker = deps.worker_id ?? `worker:${process.pid ?? 0}`;
  const handlers: Record<string, JobHandler> = {
    cache_invalidate_keys: async (payload, d) => {
      const key_ids = (payload['key_ids'] ?? []) as ReadonlyArray<string>;
      if (!Array.isArray(key_ids)) return;
      for (const kid of key_ids) {
        if (typeof kid !== 'string' || !kid.startsWith('agk_')) continue;
        await invalidateKey(d.redis, kid);
      }
    },
    ...(deps.extra_handlers ?? {}),
  };

  let completed = 0;
  let failed = 0;
  let dead = 0;
  let inspected = 0;

  for (let i = 0; i < batch; i++) {
    // 1) Lock + claim a single runnable job. Each iteration is its own
    //    short tx — keeps the row lock window tiny.
    const claim = await deps.postgres.transaction(async (client) => {
      const row = await client.query<AgentJobRow>(
        `SELECT id::text AS id, kind, payload, attempts, max_attempts
           FROM agent_jobs
          WHERE status = 'pending' AND run_at <= now()
          ORDER BY id ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1`,
      );
      const j = row.rows[0];
      if (!j) return null;
      await client.query(
        `UPDATE agent_jobs
            SET status = 'running', locked_at = now(), locked_by = $2
          WHERE id = $1::bigint`,
        [j.id, worker],
      );
      return j;
    });
    if (!claim) break; // nothing to do
    inspected++;

    const handler = handlers[claim.kind];
    if (!handler) {
      // Unknown kind — mark completed (no-op) so it doesn't loop.
      await deps.postgres
        .query(
          `UPDATE agent_jobs
              SET status = 'completed', completed_at = now(), locked_at = NULL, locked_by = NULL
            WHERE id = $1::bigint`,
          [claim.id],
        )
        .catch(() => undefined);
      deps.onAlert?.('agent_jobs_unknown_kind', {
        id: claim.id,
        kind: claim.kind,
      });
      completed++;
      continue;
    }

    try {
      await handler(claim.payload, { postgres: deps.postgres, redis: deps.redis });
      await deps.postgres.query(
        `UPDATE agent_jobs
            SET status = 'completed', completed_at = now(), locked_at = NULL, locked_by = NULL
          WHERE id = $1::bigint`,
        [claim.id],
      );
      completed++;
    } catch (err) {
      const next_attempts = claim.attempts + 1;
      if (next_attempts >= claim.max_attempts) {
        await deps.postgres
          .query(
            // Set completed_at on dead too — both 'completed' and
            // 'dead' are terminal, and the reaper uses completed_at
            // as the "finished" timestamp regardless of which.
            `UPDATE agent_jobs
                SET status = 'dead', attempts = $2,
                    last_error = $3,
                    completed_at = now(),
                    locked_at = NULL, locked_by = NULL
              WHERE id = $1::bigint`,
            [claim.id, next_attempts, errorMessage(err).slice(0, 500)],
          )
          .catch(() => undefined);
        dead++;
        deps.onAlert?.('agent_jobs_dead_lettered', {
          id: claim.id,
          kind: claim.kind,
          attempts: next_attempts,
        });
      } else {
        await deps.postgres
          .query(
            `UPDATE agent_jobs
                SET status = 'pending', attempts = $2,
                    last_error = $3,
                    locked_at = NULL, locked_by = NULL
              WHERE id = $1::bigint`,
            [claim.id, next_attempts, errorMessage(err).slice(0, 500)],
          )
          .catch(() => undefined);
        failed++;
      }
    }
  }

  return { inspected, completed, failed, dead };
}

function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return 'unknown_error';
}
