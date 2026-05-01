/**
 * Reaper — deletes expired registration sessions (§3.6 footer). Runs every
 * minute as a cron-style worker. Idempotent and bounded by the server-side
 * `expires_at < now() - 1h` filter.
 *
 * Other reapers (idempotency expiry, audit-outbox flush) live in their own
 * files for clarity.
 */

import { RegistrationSessionRepo } from '../storage/registration-session-repo.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface ReaperResult {
  readonly registration_sessions_deleted: number;
}

export async function reapRegistrationSessions(
  pg: PostgresAdapter,
  now: Date = new Date(),
): Promise<ReaperResult> {
  const repo = new RegistrationSessionRepo(pg);
  const deleted = await repo.deleteExpired(now);
  return { registration_sessions_deleted: deleted };
}
