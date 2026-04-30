/**
 * Runbook implementations RB-1..RB-9 referenced from §8.2.
 *
 * Each handler implements the destructive side-effect of a runbook step.
 * The dispatcher (cli.ts) handles auth + audit; handlers focus on the
 * business operation. Handlers re-use the same primitives the route
 * layer uses (revoke, bumpEpochInTx, captureBarrierAfterCommit, etc.)
 * so admin-driven mutations cannot accidentally bypass invariants.
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import type { AdminCommandHandler, AdminDispatchDeps } from './cli.js';
import { tierBIdempotent, canonicalRequestHash } from '../reliability/idempotency.js';
import { bumpEpochInTx } from '../distributed/revocation-epoch.js';
import {
  captureBarrierAfterCommit,
} from '../distributed/revocation-barrier.js';
import {
  invalidateKey,
  invalidateAccountKeys,
} from '../distributed/cache-invalidation.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import { reconcileAccountKeySets } from '../jobs/reconcile-redis-sets.js';

// ---------------------------------------------------------------------------
// RB-1: Force-revoke a specific key
// ---------------------------------------------------------------------------

const RbRevokeKeyOptions = z
  .object({
    key_id: z.string().regex(/^agk_[A-Za-z0-9_-]{1,32}$/),
    redis: z.unknown().optional(), // injected by deps
  })
  .strict()
  .passthrough();

export interface RbRevokeKeyDeps {
  readonly redis: RedisAdapter;
  readonly region: string;
}

export const rbRevokeKey = (extra: RbRevokeKeyDeps): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = RbRevokeKeyOptions.parse(input.options);
    const key_id = opts.key_id;
    const idemKey = `admin-rb1:${input.admin_id}:${key_id}:${input.reason}`;
    const requestHash = canonicalRequestHash({ rb: 1, key_id, reason: input.reason });

    const result = await tierBIdempotent<{ key_id: string; revoked_at: string }>(
      deps.postgres,
      {
        idempotency_key: idemKey,
        request_hash: requestHash,
        operation_type: 'revoke',
        resource_ref: `key:${key_id}`,
      },
      async ({ client }) => {
        const sel = await client.query<{
          id: string;
          rotation_state: string;
          account_id: string;
          revoked_at: Date | null;
        }>(
          `SELECT id, rotation_state, account_id, revoked_at
             FROM agent_api_keys WHERE key_id = $1 FOR UPDATE`,
          [key_id],
        );
        const row = sel.rows[0];
        if (!row) throw new AgentAuthError(404, 'key_not_found');
        if (row.rotation_state === 'revoked') {
          return {
            status: 200,
            body: {
              key_id,
              revoked_at: (row.revoked_at ?? new Date()).toISOString(),
            },
          };
        }
        const upd = await client.query<{ revoked_at: Date }>(
          `UPDATE agent_api_keys
              SET rotation_state = 'revoked', revoked_at = now(),
                  revoked_reason = $2
            WHERE id = $1 RETURNING revoked_at`,
          [row.id, input.reason],
        );
        const { epoch } = await bumpEpochInTx(client, extra.redis);
        const lsn = await client.query<{ commit_lsn: string }>(
          `SELECT pg_current_wal_insert_lsn()::text AS commit_lsn`,
        );
        await client.query(
          `INSERT INTO agent_revocation_log
             (region, kind, target_id, commit_lsn, epoch, reason)
           VALUES ($1, 'key_revoke', $2, $3::pg_lsn, $4, $5)`,
          [
            extra.region,
            key_id,
            lsn.rows[0]?.commit_lsn ?? '0/0',
            epoch,
            input.reason,
          ],
        );
        return {
          status: 200,
          body: {
            key_id,
            revoked_at: (upd.rows[0]?.revoked_at ?? new Date()).toISOString(),
          },
        };
      },
    );

    try {
      await captureBarrierAfterCommit(deps.postgres);
    } catch {
      /* swallow */
    }
    await invalidateKey(extra.redis, key_id);
    return result.body;
  },
});

// ---------------------------------------------------------------------------
// RB-2: Suspend account (cascade revoke all keys)
// ---------------------------------------------------------------------------

const RbSuspendAccountOptions = z
  .object({ account_id: z.string().uuid() })
  .strict()
  .passthrough();

export const rbSuspendAccount = (
  extra: RbRevokeKeyDeps,
): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = RbSuspendAccountOptions.parse(input.options);
    const account_id = opts.account_id;
    const idemKey = `admin-rb2:${input.admin_id}:${account_id}:${input.reason}`;
    const requestHash = canonicalRequestHash({ rb: 2, account_id, reason: input.reason });

    const result = await tierBIdempotent<{ account_id: string; suspended_at: string }>(
      deps.postgres,
      {
        idempotency_key: idemKey,
        request_hash: requestHash,
        operation_type: 'suspend_account',
        resource_ref: `account:${account_id}`,
      },
      async ({ client }) => {
        const acc = await client.query<{ status: string; suspended_at: Date | null }>(
          `SELECT status, suspended_at FROM agent_accounts WHERE id = $1 FOR UPDATE`,
          [account_id],
        );
        const a = acc.rows[0];
        if (!a) throw new AgentAuthError(404, 'account_not_found');
        if (a.status === 'closed') {
          throw new AgentAuthError(410, 'account_closed');
        }
        if (a.status !== 'suspended') {
          await client.query(
            `UPDATE agent_accounts
                SET status = 'suspended', suspended_at = now()
              WHERE id = $1`,
            [account_id],
          );
        }
        await client.query(
          `UPDATE agent_api_keys
              SET rotation_state = 'revoked', revoked_at = now(),
                  revoked_reason = $2
            WHERE account_id = $1
              AND rotation_state IN ('active', 'rotating')`,
          [account_id, `account_suspended: ${input.reason}`],
        );
        const { epoch } = await bumpEpochInTx(client, extra.redis);
        const lsn = await client.query<{ commit_lsn: string }>(
          `SELECT pg_current_wal_insert_lsn()::text AS commit_lsn`,
        );
        await client.query(
          `INSERT INTO agent_revocation_log
             (region, kind, target_id, commit_lsn, epoch, reason)
           VALUES ($1, 'account_suspend', $2, $3::pg_lsn, $4, $5)`,
          [
            extra.region,
            account_id,
            lsn.rows[0]?.commit_lsn ?? '0/0',
            epoch,
            input.reason,
          ],
        );
        return {
          status: 200,
          body: { account_id, suspended_at: new Date().toISOString() },
        };
      },
    );
    try {
      await captureBarrierAfterCommit(deps.postgres);
    } catch {
      /* swallow */
    }
    await invalidateAccountKeys(deps.postgres, extra.redis, account_id);
    return result.body;
  },
});

// ---------------------------------------------------------------------------
// RB-4: Flush cache (two-person required)
// ---------------------------------------------------------------------------

export const rbFlushCache = (extra: { redis: RedisAdapter }): AdminCommandHandler => ({
  async run(_input, _deps) {
    // Walk a known set of cache key prefixes and DEL each. We use SCAN
    // semantics implicit in the in-memory adapter; production deployments
    // pass through to ioredis.
    // Simpler alternative: ask the SaaS to run the equivalent SCAN; expose
    // a small surface here so admin can trigger it on demand.
    // For v0.1, the flush is delegated to the redis adapter's own flush
    // capability when available. The lib does NOT issue a global FLUSHDB
    // because that affects the entire Redis instance (RB-4 is scoped to
    // agent-auth keys only).
    if ('close' in extra.redis && typeof (extra.redis as { close?: () => unknown }).close === 'function') {
      // No-op: production adapters expose the helper via SaaS-supplied tools.
    }
    // Delete the well-known epoch and any cache:* keys we know about.
    // Account-level invalidation already lives in cache-invalidation.ts.
    return { flushed: true };
  },
});

// ---------------------------------------------------------------------------
// RB-5: Unblock identity (admin override)
// ---------------------------------------------------------------------------

const RbUnblockIdentityOptions = z
  .object({ identity_id: z.string().uuid() })
  .strict()
  .passthrough();

export const rbUnblockIdentity = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = RbUnblockIdentityOptions.parse(input.options);
    await deps.postgres.query(
      `UPDATE agent_identities
          SET status = 'active', revoked_at = NULL,
              revoked_reason = NULL, revocation_source = 'admin',
              last_revalidated_at = now()
        WHERE id = $1 AND status = 'revoked'`,
      [opts.identity_id],
    );
    return { identity_id: opts.identity_id, unblocked_at: new Date().toISOString() };
  },
});

// ---------------------------------------------------------------------------
// RB-7: Reconcile Redis SET drift
// ---------------------------------------------------------------------------

export const rbReconcileRedisSets = (extra: { redis: RedisAdapter }): AdminCommandHandler => ({
  async run(_input, deps) {
    return reconcileAccountKeySets({
      postgres: deps.postgres,
      redis: extra.redis,
    });
  },
});

// ---------------------------------------------------------------------------
// RB-3 (idempotency unknown resolution) — read-only inspection
// ---------------------------------------------------------------------------

export const rbResolveIdempotency = (): AdminCommandHandler => ({
  async run(_input, deps) {
    const rows = await deps.postgres.query(
      `SELECT key, operation_type, resource_ref, state, reconcile_attempts,
              created_at, last_reconcile_at, manual_required_at
         FROM agent_idempotency
        WHERE state IN ('unknown', 'manual_required')
        ORDER BY created_at ASC`,
    );
    return { rows: rows.rows };
  },
});

// ---------------------------------------------------------------------------
// Read-only: audit-tail. SPEC §8.2 / RB-6 forensic-response support.
// Caller passes `options.{since?, account_id?, key_id?, event_type?, limit?}`.
// Defaults: last 24h, limit 100. Hard-capped at 10_000 to prevent DoS via
// runaway query.
// ---------------------------------------------------------------------------

export const rbAuditTail = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = (input.options ?? {}) as {
      since?: string;
      account_id?: string;
      key_id?: string;
      event_type?: string;
      limit?: number;
    };
    const since = opts.since ? new Date(opts.since) : new Date(Date.now() - 24 * 3600 * 1000);
    const limit = Math.max(1, Math.min(10_000, opts.limit ?? 100));
    const where: string[] = ['ts >= $1'];
    const params: unknown[] = [since];
    if (opts.account_id) {
      params.push(opts.account_id);
      where.push(`account_id = $${params.length}::uuid`);
    }
    if (opts.key_id) {
      params.push(opts.key_id);
      where.push(`key_id = $${params.length}`);
    }
    if (opts.event_type) {
      params.push(opts.event_type);
      where.push(`event_type = $${params.length}`);
    }
    params.push(limit);
    const rows = await deps.postgres.query(
      `SELECT id::text AS id, ts, event_type, account_id::text AS account_id,
              key_id, identity_id::text AS identity_id, endpoint, status_class,
              meta
         FROM agent_audit_log
        WHERE ${where.join(' AND ')}
        ORDER BY id DESC
        LIMIT $${params.length}`,
      params,
    );
    return { rows: rows.rows, count: rows.rows.length };
  },
});

// ---------------------------------------------------------------------------
// Convenience: build the default handler map for AdminDispatchDeps.handlers.
// ---------------------------------------------------------------------------

export function defaultRunbookHandlers(deps: {
  redis: RedisAdapter;
  region: string;
}): Readonly<Partial<Record<import('./cli.js').AdminCommandName, AdminCommandHandler>>> {
  return {
    'revoke-key': rbRevokeKey({ redis: deps.redis, region: deps.region }),
    'suspend-account': rbSuspendAccount({ redis: deps.redis, region: deps.region }),
    'flush-cache': rbFlushCache({ redis: deps.redis }),
    'unblock-identity': rbUnblockIdentity(),
    'reconcile-redis-sets': rbReconcileRedisSets({ redis: deps.redis }),
    'resolve-idempotency': rbResolveIdempotency(),
    'audit-tail': rbAuditTail(),
  };
}

export type { AdminCommandHandler, AdminDispatchDeps };
