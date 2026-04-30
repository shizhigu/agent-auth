/**
 * LSN barrier maintenance. SPEC §4.4.2.
 *
 * After a Tier B revocation commits on primary, we capture the WAL insert
 * position and update the singleton barrier row. Secondary regions consult
 * this barrier when validating to detect stale-replica scenarios (§4.4.2
 * read path; integrated into validateKey in M6).
 *
 * In v0.1 single-region deployment the barrier still runs (cheap). It only
 * matters for correctness in multi-region; locally it's a fast UPDATE.
 *
 * Sequence relative to the commit (per §4.4.2 step 2):
 *   1. Tier B mutation commits.
 *   2. captureBarrierAfterCommit() reads pg_current_wal_insert_lsn()
 *      and UPDATEs agent_revocation_barrier.
 *   3. (Optional) caller appends to agent_revocation_log with this LSN.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface BarrierUpdate {
  /** Captured LSN as a Postgres pg_lsn string ('X/Y'). */
  readonly commit_lsn: string;
  /** Timeline that produced this LSN (1 in single-region; >1 after failover). */
  readonly timeline_id: number;
}

/**
 * Capture the post-commit LSN and advance the global barrier.
 *
 * MUST run AFTER the Tier B transaction commits. Calling inside the same
 * transaction would record the in-progress WAL position, not the durable
 * commit one. Caller is responsible for ordering.
 */
export async function captureBarrierAfterCommit(
  pg: PostgresAdapter,
): Promise<BarrierUpdate> {
  const lsnRes = await pg.queryOne<{ lsn: string }>(
    `SELECT pg_current_wal_insert_lsn()::text AS lsn`,
  );
  if (!lsnRes) throw new Error('barrier_lsn_query_returned_no_row');
  const commit_lsn = lsnRes.lsn;

  const tlRes = await pg.queryOne<{ timeline_id: number }>(
    `SELECT timeline_id FROM pg_control_checkpoint()`,
  );
  const timeline_id = tlRes?.timeline_id ?? 1;

  await pg.query(
    `UPDATE agent_revocation_barrier
        SET last_lsn = GREATEST(last_lsn, $1::pg_lsn),
            timeline_id = GREATEST(timeline_id, $2),
            updated_at = now()
      WHERE id = 1`,
    [commit_lsn, timeline_id],
  );
  return { commit_lsn, timeline_id };
}

/** Read the authoritative barrier (used by secondary-region validation). */
export interface BarrierSnapshot {
  readonly last_lsn: string;
  readonly timeline_id: number;
}

export async function readAuthoritativeBarrier(
  pg: PostgresAdapter,
): Promise<BarrierSnapshot> {
  const row = await pg.queryOne<{ last_lsn: string; timeline_id: number }>(
    `SELECT last_lsn::text AS last_lsn, timeline_id
       FROM agent_revocation_barrier WHERE id = 1`,
  );
  if (!row) throw new Error('barrier_singleton_missing');
  return row;
}
