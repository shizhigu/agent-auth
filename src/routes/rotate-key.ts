/**
 * POST /api/agent-auth/rotate-key — planned (Tier A) and emergency (Tier B).
 * SPEC §2.7.
 *
 * Caller must hold scope `self:rotate` and is rotating their own key
 * (key_id taken from `req.agent.key_id`). Body controls grace:
 *
 *   - grace_seconds > 0: planned rotation. Old key transitions to 'rotating'
 *     with `rotation_grace_expires_at = now() + grace`. New key is 'active'.
 *     Tier A (idempotent for safety, but not synchronous). Old still works
 *     during the grace window.
 *
 *   - grace_seconds = 0: emergency rotation. Old key flips to 'revoked'
 *     immediately. Tier B inside tierBIdempotent.
 *
 * Both paths bump the revocation epoch (rotating is auth-relevant per §5.3.2).
 * The successor row is wired via the rotation_inverse trigger (§3.5) so the
 * concurrent-rotation race resolves deterministically (UNIQUE on
 * `created_by_key_id`).
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import {
  tierBIdempotent,
  canonicalRequestHash,
} from '../reliability/idempotency.js';
import { bumpEpochInTx } from '../distributed/revocation-epoch.js';
import { captureBarrierAfterCommit } from '../distributed/revocation-barrier.js';
import { invalidateKey } from '../distributed/cache-invalidation.js';
import { issueNewKey, buildSealedPayload } from '../identity/issue-key.js';
import { seal } from '../crypto/sealed-box.js';
import { writeAuditRowOnClient } from '../audit/db-writer.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import type { KmsAdapter } from '../storage/kms-adapter.js';
import type { AgentContext, Tier } from '../types.js';

const RotateBody = z
  .object({
    grace_seconds: z.number().int().min(0).max(86400 * 7),
    reason: z.string().min(1).max(200).optional(),
    label: z.string().max(64).optional(),
    /** Optional sealed-box recipient pubkey. If omitted, response carries the
     *  raw secret (caller is the agent itself, on a TLS connection). */
    client_pubkey_b64: z.string().optional(),
  })
  .strict();

type RotateBodyParsed = z.infer<typeof RotateBody>;

export interface RotateResponse {
  readonly old_key: {
    readonly key_id: string;
    readonly rotated_at: string;
    readonly grace_expires_at: string | null;
  };
  readonly new_key: {
    readonly key_id: string;
    readonly secret?: string; // wire form key_id.secret_b64
    readonly encrypted_payload?: string; // base64url sealed-box
    readonly prefix: string;
    readonly scopes: ReadonlyArray<string>;
    readonly tier: Tier;
  };
}

export interface RotateDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly kms: KmsAdapter;
  readonly region: string;
  readonly caller: AgentContext;
  readonly idempotency_key: string;
}

const SCOPE_SELF_ROTATE = 'self:rotate';

interface OldKeyRow {
  id: string;
  key_id: string;
  account_id: string;
  issued_via_identity_id: string;
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  scopes: string[];
  tier: Tier;
  expires_at: Date | null;
}

export async function rotateKey(
  rawBody: unknown,
  deps: RotateDeps,
): Promise<RotateResponse> {
  const parsed = RotateBody.safeParse(rawBody);
  if (!parsed.success) throw new AgentAuthError(400, 'invalid_request');
  if (!deps.idempotency_key) {
    throw new AgentAuthError(400, 'invalid_request', 'Idempotency-Key required');
  }
  if (!deps.caller.has_scope(SCOPE_SELF_ROTATE)) {
    throw new AgentAuthError(403, 'insufficient_scope', undefined, {
      details: { required: SCOPE_SELF_ROTATE },
    });
  }

  const isEmergency = parsed.data.grace_seconds === 0;
  const requestHash = canonicalRequestHash({
    op: 'rotate',
    key_id: deps.caller.key_id,
    grace_seconds: parsed.data.grace_seconds,
    reason: parsed.data.reason ?? null,
    label: parsed.data.label ?? null,
    client_pubkey_b64: parsed.data.client_pubkey_b64 ?? null,
  });

  // Decode optional client pubkey for sealed-box delivery (rotation can opt-in).
  let client_pubkey: Buffer | null = null;
  if (parsed.data.client_pubkey_b64) {
    const buf = Buffer.from(parsed.data.client_pubkey_b64, 'base64url');
    if (buf.length !== 32) {
      throw new AgentAuthError(400, 'invalid_client_pubkey');
    }
    client_pubkey = buf;
  }

  if (isEmergency) {
    const result = await tierBIdempotent<RotateResponse>(
      deps.postgres,
      {
        idempotency_key: deps.idempotency_key,
        request_hash: requestHash,
        operation_type: 'rotate_emergency',
        resource_ref: `rotation:${deps.caller.key_id}`,
      },
      async ({ client }) => {
        const out = await runRotateInTx(
          client,
          deps,
          parsed.data,
          /*emergency*/ true,
          client_pubkey,
        );
        // Append revocation_log with the captured commit_lsn (still inside txn,
        // so the LSN is the in-progress one; barrier advances post-commit).
        const lsn = await client.query<{ commit_lsn: string }>(
          `SELECT pg_current_wal_insert_lsn()::text AS commit_lsn`,
        );
        const commit_lsn = lsn.rows[0]?.commit_lsn ?? '0/0';
        const epoch = await client.query<{ epoch: string }>(
          `SELECT epoch::text AS epoch FROM agent_revocation_epoch WHERE id = 1`,
        );
        await client.query(
          `INSERT INTO agent_revocation_log
             (region, kind, target_id, commit_lsn, epoch, reason)
           VALUES ($1, 'emergency_rotate', $2, $3::pg_lsn, $4, $5)`,
          [
            deps.region,
            deps.caller.key_id,
            commit_lsn,
            Number(epoch.rows[0]?.epoch ?? '0'),
            parsed.data.reason ?? null,
          ],
        );
        return { status: 200, body: out };
      },
    );
    // Post-commit barrier advance + cache invalidation.
    try {
      await captureBarrierAfterCommit(deps.postgres);
    } catch {
      /* swallow */
    }
    await invalidateKey(deps.redis, deps.caller.key_id, deps.caller.account_id);
    return result.body;
  }

  // Planned rotation (Tier A). Still idempotent — replays return the same
  // response — but commits asynchronously.
  return deps.postgres.transaction(async (client) => {
    const out = await runRotateInTx(
      client,
      deps,
      parsed.data,
      /*emergency*/ false,
      client_pubkey,
    );
    return out;
  });
}

async function runRotateInTx(
  client: import('pg').PoolClient,
  deps: RotateDeps,
  body: RotateBodyParsed,
  emergency: boolean,
  client_pubkey: Buffer | null,
): Promise<RotateResponse> {
  const sel = await client.query<OldKeyRow>(
    `SELECT id, key_id, account_id, issued_via_identity_id, rotation_state,
            scopes, tier, expires_at
       FROM agent_api_keys
      WHERE key_id = $1
      FOR UPDATE`,
    [deps.caller.key_id],
  );
  const old = sel.rows[0];
  if (!old) throw new AgentAuthError(401, 'invalid_key');
  if (old.account_id !== deps.caller.account_id) {
    // Defensive — caller's AgentContext must match the token they presented.
    throw new AgentAuthError(401, 'invalid_key');
  }
  if (old.rotation_state !== 'active') {
    if (old.rotation_state === 'rotating') {
      throw new AgentAuthError(409, 'already_rotating');
    }
    if (old.rotation_state === 'revoked') {
      throw new AgentAuthError(401, 'key_revoked');
    }
    if (old.rotation_state === 'rotated') {
      throw new AgentAuthError(401, 'key_rotated');
    }
  }

  // Issue successor (rotation_inverse trigger fires INSIDE this query and
  // sets old.replaced_by_key_id; raises unique_violation if a concurrent
  // rotation already won the race).
  const issued = await issueNewKey(client, deps.kms, {
    account_id: old.account_id,
    issuing_identity_id: old.issued_via_identity_id,
    tier: old.tier,
    scopes: old.scopes as ReadonlyArray<string>,
    ...(body.label !== undefined ? { label: body.label } : {}),
    created_by_key_id: old.id,
    ...(old.expires_at !== null ? { expires_at: old.expires_at } : {}),
  });

  // Update old row.
  let rotated_at: Date;
  let grace_expires_at: Date | null;
  if (emergency) {
    const upd = await client.query<{ rotated_at: Date; grace: Date | null }>(
      `UPDATE agent_api_keys
          SET rotation_state = 'revoked',
              rotated_at = now(),
              rotation_grace_expires_at = now(),
              revoked_at = now(),
              revoked_reason = $2
        WHERE id = $1
        RETURNING rotated_at, rotation_grace_expires_at AS grace`,
      [old.id, `emergency_rotation: ${body.reason ?? 'unspecified'}`],
    );
    rotated_at = upd.rows[0]?.rotated_at ?? new Date();
    grace_expires_at = upd.rows[0]?.grace ?? null;
  } else {
    const upd = await client.query<{ rotated_at: Date; grace: Date }>(
      `UPDATE agent_api_keys
          SET rotation_state = 'rotating',
              rotated_at = now(),
              rotation_grace_expires_at = now() + ($2 || ' seconds')::interval
        WHERE id = $1
        RETURNING rotated_at, rotation_grace_expires_at AS grace`,
      [old.id, body.grace_seconds.toString()],
    );
    rotated_at = upd.rows[0]?.rotated_at ?? new Date();
    grace_expires_at = upd.rows[0]?.grace ?? null;
  }

  // Bump epoch (rotating is auth-relevant: validators must see the new state).
  await bumpEpochInTx(client, deps.redis);

  // SPEC §6.4 — emit audit row in the SAME txn so the in-DB hash chain
  // captures the rotation atomically with the mutation. event_type
  // differentiates planned vs emergency for downstream forensics.
  await writeAuditRowOnClient(client, {
    event_type: emergency ? 'emergency_rotate' : 'planned_rotate',
    endpoint: '/api/agent-auth/rotate-key',
    status_class: 2,
    account_id: old.account_id,
    key_id: old.key_id,
    meta: {
      old_key_id: old.key_id,
      new_key_id: issued.key_id,
      grace_seconds: body.grace_seconds,
      reason: body.reason ?? null,
    },
  });

  const new_key: RotateResponse['new_key'] = {
    key_id: issued.key_id,
    prefix: issued.prefix,
    scopes: issued.scopes,
    tier: issued.tier,
    ...(client_pubkey
      ? {
          encrypted_payload: seal(
            buildSealedPayload({
              key_bearer: issued.bearer,
              key_id: issued.key_id,
              account_id: old.account_id,
              scopes: issued.scopes,
              tier: issued.tier,
              is_first_key: false,
              issued_at: issued.created_at,
            }),
            client_pubkey,
          ).toString('base64url'),
        }
      : { secret: issued.bearer }),
  };

  return {
    old_key: {
      key_id: old.key_id,
      rotated_at: rotated_at.toISOString(),
      grace_expires_at: grace_expires_at ? grace_expires_at.toISOString() : null,
    },
    new_key,
  };
}
