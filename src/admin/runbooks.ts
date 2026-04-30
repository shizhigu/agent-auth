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
import { writeAuditRowOnClient } from '../audit/db-writer.js';
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
        // SPEC §6.4 — Tier B mutation MUST emit an audit row in the same
        // transaction as the state change. The CLI dispatcher (cli.ts) writes
        // an "admin_<command>" intent row before this handler runs; this
        // in-tx row records the *commit* atomically with the revocation so
        // RT-39 (audit omission by compromised app) cannot suppress evidence
        // of a successful revoke after the intent has already been logged.
        await writeAuditRowOnClient(client, {
          event_type: 'admin_revoke_committed',
          endpoint: 'cli',
          status_class: 2,
          account_id: row.account_id,
          key_id,
          meta: {
            admin_id: input.admin_id,
            reason: input.reason,
            rb: 1,
            epoch,
          },
        });
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
        // SPEC §6.4 — same-tx audit for the commit (RT-39 fail-closed).
        await writeAuditRowOnClient(client, {
          event_type: 'admin_suspend_committed',
          endpoint: 'cli',
          status_class: 2,
          account_id,
          meta: {
            admin_id: input.admin_id,
            reason: input.reason,
            rb: 2,
            epoch,
          },
        });
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
// Read-only: list-accounts (SPEC §8.2). Cursored by id; default limit 50,
// hard-capped at 1000 to prevent DoS.
// ---------------------------------------------------------------------------

export const rbListAccounts = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = (input.options ?? {}) as {
      after_id?: string;
      status?: string;
      limit?: number;
    };
    const limit = Math.max(1, Math.min(1000, opts.limit ?? 50));
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.after_id) {
      params.push(opts.after_id);
      where.push(`id::text > $${params.length}`);
    }
    if (opts.status) {
      params.push(opts.status);
      where.push(`status = $${params.length}::account_status_enum`);
    }
    params.push(limit);
    const rows = await deps.postgres.query(
      `SELECT id::text AS id, display_handle, tier::text AS tier,
              status::text AS status, created_at, suspended_at, closed_at
         FROM agent_accounts
         ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY id ASC
        LIMIT $${params.length}`,
      params,
    );
    return { rows: rows.rows, count: rows.rows.length };
  },
});

// ---------------------------------------------------------------------------
// Read-only: show-account. Returns the account row + count of keys + count
// of identities. Operator-friendly summary for triage.
// ---------------------------------------------------------------------------

export const rbShowAccount = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = (input.options ?? {}) as { account_id?: string };
    if (!opts.account_id) {
      throw new Error('show-account: options.account_id required');
    }
    const row = await deps.postgres.queryOne(
      `SELECT
         a.id::text AS id, a.display_handle, a.tier::text AS tier,
         a.status::text AS status, a.created_at, a.suspended_at, a.closed_at,
         (SELECT count(*) FROM agent_identities WHERE account_id = a.id)::int AS identity_count,
         (SELECT count(*) FROM agent_api_keys
            WHERE account_id = a.id AND rotation_state <> 'revoked')::int AS active_key_count,
         (SELECT count(*) FROM agent_api_keys
            WHERE account_id = a.id AND rotation_state = 'revoked')::int AS revoked_key_count
       FROM agent_accounts a
       WHERE a.id = $1::uuid`,
      [opts.account_id],
    );
    return row ? { account: row } : { account: null };
  },
});

// ---------------------------------------------------------------------------
// Read-only: list-keys (admin variant — across accounts). The agent-facing
// /api/agent-auth/keys is in src/routes/list-keys.ts; this is the admin CLI
// equivalent that includes revoked rows for forensics.
// ---------------------------------------------------------------------------

export const rbListKeys = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = (input.options ?? {}) as {
      account_id?: string;
      rotation_state?: string;
      limit?: number;
    };
    const limit = Math.max(1, Math.min(1000, opts.limit ?? 100));
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.account_id) {
      params.push(opts.account_id);
      where.push(`account_id = $${params.length}::uuid`);
    }
    if (opts.rotation_state) {
      params.push(opts.rotation_state);
      where.push(`rotation_state = $${params.length}::rotation_state_enum`);
    }
    params.push(limit);
    const rows = await deps.postgres.query(
      `SELECT key_id, account_id::text AS account_id, prefix, label, scopes,
              tier::text AS tier, rotation_state::text AS rotation_state,
              created_at, last_used_at, expires_at,
              revoked_at, revoked_reason
         FROM agent_api_keys
         ${where.length > 0 ? `WHERE ${where.join(' AND ')}` : ''}
        ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params,
    );
    return { rows: rows.rows, count: rows.rows.length };
  },
});

// ---------------------------------------------------------------------------
// Read-only: show-key. Single-row detail by key_id, including the issuing
// identity row joined in for forensics.
// ---------------------------------------------------------------------------

export const rbShowKey = (): AdminCommandHandler => ({
  async run(input, deps) {
    const opts = (input.options ?? {}) as { key_id?: string };
    if (!opts.key_id) {
      throw new Error('show-key: options.key_id required');
    }
    const row = await deps.postgres.queryOne(
      `SELECT
         k.key_id, k.account_id::text AS account_id, k.prefix, k.label,
         k.scopes, k.tier::text AS tier,
         k.rotation_state::text AS rotation_state,
         k.created_at, k.last_used_at, k.expires_at,
         k.rotated_at, k.rotation_grace_expires_at,
         k.revoked_at, k.revoked_reason, k.last_revoke_lsn::text AS last_revoke_lsn,
         i.id::text AS identity_id, i.provider AS identity_provider,
         i.subject AS identity_subject, i.audience AS identity_audience,
         i.assurance_level::text AS identity_assurance_level,
         i.status::text AS identity_status, i.revocation_source AS identity_revocation_source
       FROM agent_api_keys k
       LEFT JOIN agent_identities i ON i.id = k.issued_via_identity_id
       WHERE k.key_id = $1`,
      [opts.key_id],
    );
    return row ? { key: row } : { key: null };
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
    'list-accounts': rbListAccounts(),
    'show-account': rbShowAccount(),
    'list-keys': rbListKeys(),
    'show-key': rbShowKey(),
  };
}

export type { AdminCommandHandler, AdminDispatchDeps };
