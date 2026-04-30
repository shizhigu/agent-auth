/**
 * Rotation-grace expirer. SPEC §2.7.3.
 *
 * Every minute, flip every `rotation_state='rotating'` key whose
 * `rotation_grace_expires_at < now()` to `rotation_state='rotated'`.
 *
 * This is a hygiene job, not a correctness gate — validateKey already
 * rejects grace-expired rotating keys with 401 rotation_grace_expired,
 * so an unflipped row is still safe. The job's purpose is to:
 *   - clear the way for /rotate-key callers to see a clean rotation
 *     state machine (no zombie 'rotating' rows lingering after grace).
 *   - free `rotation_grace_expires_at` from being load-bearing for
 *     long-tail key states (the trigger guarantee `keys_rotated_has_grace`
 *     only requires it while state='rotating').
 *   - produce a clearer error for downstream tooling: 'key_rotated'
 *     (terminal, predecessor of a successor that is now active) vs
 *     'rotation_grace_expired' (in-flight rotation that never landed).
 *
 * No epoch bump (transition is still-rejected → still-rejected; cache
 * entries staleness is bounded by the 30 s TTL).
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface RotationGraceExpirerDeps {
  readonly postgres: PostgresAdapter;
  readonly now?: () => Date;
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface RotationGraceExpirerResult {
  readonly expired: number;
}

export async function expireRotationGrace(
  deps: RotationGraceExpirerDeps,
): Promise<RotationGraceExpirerResult> {
  const now = deps.now ? deps.now() : new Date();
  const res = await deps.postgres.query<{ key_id: string }>(
    `UPDATE agent_api_keys
        SET rotation_state = 'rotated'
      WHERE rotation_state = 'rotating'
        AND rotation_grace_expires_at IS NOT NULL
        AND rotation_grace_expires_at < $1
      RETURNING key_id`,
    [now],
  );
  const expired = res.rows.length;
  if (expired > 0) {
    deps.onAlert?.('rotation_grace_expired_batch', {
      count: expired,
      first_key_id: res.rows[0]?.key_id ?? null,
    });
  }
  return { expired };
}
