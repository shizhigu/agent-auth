/**
 * POST /api/agent-auth/revoke — Tier B revocation. SPEC §2.8.
 *
 * Caller is the agent itself (Bearer token already validated by middleware
 * — handler receives `caller: AgentContext`). Caller may revoke its own
 * key (scope `self:revoke`) or any key on the same account if it has
 * `admin:keys`.
 *
 * Tier B operation: synchronous_commit=remote_apply, idempotent via
 * Idempotency-Key header. The commit, epoch bump, barrier capture, and
 * revocation_log INSERT happen in one transaction. Post-commit, we
 * invalidate the Redis cache + PUBLISH so peers drop their local LRUs.
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import { tierBIdempotent, canonicalRequestHash } from '../reliability/idempotency.js';
import { bumpEpochInTx } from '../distributed/revocation-epoch.js';
import {
  captureBarrierAfterCommit,
} from '../distributed/revocation-barrier.js';
import { invalidateKey } from '../distributed/cache-invalidation.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import type { AgentContext } from '../types.js';

const RevokeBody = z
  .object({
    key_id: z.string().regex(/^agk_[A-Za-z0-9_-]{1,32}$/),
    reason: z.string().min(1).max(200).optional(),
  })
  .strict();

export interface RevokeResponse {
  readonly key_id: string;
  readonly revoked_at: string;
}

export interface RevokeDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly region: string;
  /** Caller's AgentContext, set by validate-key middleware. */
  readonly caller: AgentContext;
  /** Idempotency-Key header value (required for Tier B). */
  readonly idempotency_key: string;
}

interface KeyRow {
  id: string;
  key_id: string;
  account_id: string;
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  revoked_at: Date | null;
}

const SCOPE_SELF_REVOKE = 'self:revoke';
const SCOPE_ADMIN_KEYS = 'admin:keys';

export async function revoke(
  rawBody: unknown,
  deps: RevokeDeps,
): Promise<RevokeResponse> {
  const parsed = RevokeBody.safeParse(rawBody);
  if (!parsed.success) {
    throw new AgentAuthError(400, 'invalid_request');
  }
  if (!deps.idempotency_key || deps.idempotency_key.length === 0) {
    throw new AgentAuthError(400, 'invalid_request', 'Idempotency-Key required');
  }

  // Authorization. The caller must either:
  //   - hold self:revoke AND target the caller's own key, OR
  //   - hold admin:keys (any key on the same account).
  const isSelf = parsed.data.key_id === deps.caller.key_id;
  const hasSelf = deps.caller.has_scope(SCOPE_SELF_REVOKE);
  const hasAdmin = deps.caller.has_scope(SCOPE_ADMIN_KEYS);
  if (!hasAdmin && !(isSelf && hasSelf)) {
    throw new AgentAuthError(403, 'insufficient_scope', undefined, {
      details: { required: isSelf ? SCOPE_SELF_REVOKE : SCOPE_ADMIN_KEYS },
    });
  }

  const idemKey = deps.idempotency_key;
  const requestHash = canonicalRequestHash({
    op: 'revoke',
    key_id: parsed.data.key_id,
    reason: parsed.data.reason ?? null,
    caller_account_id: deps.caller.account_id,
  });

  const result = await tierBIdempotent<RevokeResponse>(
    deps.postgres,
    {
      idempotency_key: idemKey,
      request_hash: requestHash,
      operation_type: 'revoke',
      resource_ref: `key:${parsed.data.key_id}`,
    },
    async ({ client }) => {
      // Fetch + lock the key.
      const sel = await client.query<KeyRow>(
        `SELECT id, key_id, account_id, rotation_state, revoked_at
           FROM agent_api_keys
          WHERE key_id = $1
          FOR UPDATE`,
        [parsed.data.key_id],
      );
      const row = sel.rows[0];
      if (!row) {
        throw new AgentAuthError(404, 'key_not_found');
      }
      // Cross-account guard: even with admin:keys, operate within the caller's account.
      if (row.account_id !== deps.caller.account_id) {
        throw new AgentAuthError(404, 'key_not_found'); // anti-enumeration
      }

      if (row.rotation_state === 'revoked') {
        // Idempotent already-revoked: return the original revoked_at so
        // replay clients see a consistent response.
        return {
          status: 200,
          body: {
            key_id: row.key_id,
            revoked_at: (row.revoked_at ?? new Date()).toISOString(),
          },
        };
      }
      if (row.rotation_state === 'rotated') {
        // Already rotated out — treat as 409 (caller likely meant the new key).
        throw new AgentAuthError(409, 'already_revoked');
      }

      // UPDATE row to revoked.
      const upd = await client.query<{ revoked_at: Date }>(
        `UPDATE agent_api_keys
            SET rotation_state = 'revoked',
                revoked_at = now(),
                revoked_reason = $2
          WHERE id = $1
          RETURNING revoked_at`,
        [row.id, parsed.data.reason ?? null],
      );
      const revoked_at = upd.rows[0]?.revoked_at ?? new Date();

      // Bump epoch + capture LSN + append revocation_log.
      const { epoch } = await bumpEpochInTx(client, deps.redis);
      const lsnRes = await client.query<{ commit_lsn: string }>(
        `SELECT pg_current_wal_insert_lsn()::text AS commit_lsn`,
      );
      const commit_lsn = lsnRes.rows[0]?.commit_lsn ?? '0/0';
      await client.query(
        `INSERT INTO agent_revocation_log
           (region, kind, target_id, commit_lsn, epoch, reason)
         VALUES ($1, 'key_revoke', $2, $3::pg_lsn, $4, $5)`,
        [deps.region, parsed.data.key_id, commit_lsn, epoch, parsed.data.reason ?? null],
      );
      // Update per-key barrier optimization (not correctness; see §3.5 comment).
      await client.query(
        `UPDATE agent_api_keys SET last_revoke_lsn = $2::pg_lsn WHERE id = $1`,
        [row.id, commit_lsn],
      );

      return {
        status: 200,
        body: {
          key_id: row.key_id,
          revoked_at: revoked_at.toISOString(),
        },
      };
    },
  );

  // Post-commit: advance the global barrier and invalidate Redis cache. These
  // are best-effort relative to correctness — Postgres + epoch are the
  // authoritative gates. We swallow errors here; the reconciler/observer
  // closes any drift (M5 metrics + alerts will surface it).
  try {
    await captureBarrierAfterCommit(deps.postgres);
  } catch {
    /* swallow — barrier advance retried by the reconciler */
  }
  await invalidateKey(deps.redis, parsed.data.key_id, deps.caller.account_id);

  return result.body;
}
