/**
 * Tier B commit wrapper. SPEC §4.3.
 *
 * `synchronous_commit = remote_apply` is set on the transaction (caller's
 * responsibility — postgres-adapter's transaction() supports `SET LOCAL`
 * preludes, see `tierBTransaction` below). On standby unreachable, postgres
 * returns SQLSTATE XX098 and the caller's UPDATE blocks until standby
 * answers. We wrap with a hard timeout so a stuck commit becomes a 503
 * `durability_unconfirmed` rather than a hung request.
 *
 * Outcome unknown: when the wall-clock timeout fires, the COMMIT MIGHT have
 * succeeded on primary (ack to standby was lost). The idempotency observer
 * (§5.1.2 reconcileUnknownIdempotency) is responsible for resolving the row.
 *
 * Default timeout: 5000 ms. Most production commits land in <50 ms; 5 s is
 * a generous "the standby is gone" threshold.
 */

import { ServiceUnavailableError } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { PoolClient } from 'pg';

export class TierBTimeoutError extends Error {
  override readonly name = 'TierBTimeoutError';
  constructor() {
    super('tier_b_commit_timeout');
  }
}

export interface TierBCommitOptions {
  /** Hard timeout in ms; default 5000. Override for tests. */
  readonly timeout_ms?: number;
}

/**
 * Race a Tier B operation against a wall-clock timeout. On timeout, emit
 * `durability_unconfirmed` (the operation may or may not have committed).
 * On Postgres XX098 (synchronous_commit failed: standby unreachable) emit
 * `durability_unavailable`.
 */
export async function tierBCommit<T>(
  operation: () => Promise<T>,
  options: TierBCommitOptions = {},
): Promise<T> {
  const ms = options.timeout_ms ?? 5000;
  let timeoutHandle: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(() => reject(new TierBTimeoutError()), ms);
  });
  // Start the operation. If the timeout wins the Promise.race, the operation
  // is still pending — Promise.race does NOT cancel the loser. To avoid an
  // unhandled rejection when the operation eventually fails (e.g., the slow
  // commit ultimately errors with XX098 *after* we've already returned 503),
  // attach a no-op .catch() to swallow the late rejection. Resolved values
  // are silently discarded.
  const opPromise = operation();
  opPromise.catch(() => undefined);
  try {
    return await Promise.race([opPromise, timeoutPromise]);
  } catch (err) {
    if (err instanceof TierBTimeoutError) {
      throw new ServiceUnavailableError('durability_unconfirmed', undefined, { cause: err });
    }
    if (isStandbyUnreachable(err)) {
      throw new ServiceUnavailableError('durability_unavailable', undefined, { cause: err });
    }
    throw err;
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }
}

/**
 * Convenience: open a Tier B transaction. Sets `SET LOCAL synchronous_commit
 * = remote_apply` before the BEGIN-wrapped block (postgres-adapter wraps
 * the work in BEGIN/COMMIT, so SET LOCAL is scoped to the txn).
 */
export async function tierBTransaction<T>(
  pg: PostgresAdapter,
  fn: (client: PoolClient) => Promise<T>,
  options: TierBCommitOptions = {},
): Promise<T> {
  return tierBCommit(
    () =>
      pg.transaction(async (client) => {
        await client.query("SET LOCAL synchronous_commit = 'remote_apply'");
        return fn(client);
      }),
    options,
  );
}

function isStandbyUnreachable(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  // pg uses SQLSTATE 'XX098' for synchronous_commit failure (sync standby
  // unreachable). The driver places it on `code` for parsed errors.
  const code = (err as { code?: unknown }).code;
  return code === 'XX098';
}
