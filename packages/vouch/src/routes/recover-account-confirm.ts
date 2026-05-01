/**
 * POST /api/agent-auth/recover-account-confirm/<token> — owner approve/deny
 * webhook target. SPEC §2.9 / RT-19 / RT-41.
 *
 * The owner's UI (or an automated workflow) calls this endpoint with:
 *   - approval_url_token in the URL path (lookup key)
 *   - signed metadata headers (X-Agent-Auth-Signature/Timestamp/Nonce/Request-Id)
 *   - body: { decision: 'approved' | 'denied', reason?: string }
 *
 * Steps:
 *   1. Verify the canonical HMAC + skew tolerance (verifyInboundOwnerApproval).
 *   2. Reject replay via Redis SET NX EX on the nonce (RT-19).
 *   3. Look up the agent_recovery_approvals row by token; reject if expired
 *      or already decided.
 *   4. UPDATE row with decision + reason; mark `decision_at = now()`.
 *   5. Return 200 with the resolved decision (idempotent on the same nonce).
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import { verifyInboundOwnerApproval } from '../identity/owner-approval-sign.js';
import { writeAuditRowOnClient } from '../audit/db-writer.js';
import { issueNewKey, buildSealedPayload } from '../identity/issue-key.js';
import { seal } from '../crypto/sealed-box.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import type { KmsAdapter } from '../storage/kms-adapter.js';
import type { Tier } from '../types.js';

const ConfirmBody = z
  .object({
    decision: z.enum(['approved', 'denied']),
    reason: z.string().min(1).max(500).optional(),
  })
  .strict();

const NONCE_TTL_SECONDS = 24 * 3600;
const NONCE_KEY_PREFIX = 'agent-auth:owner-approval-nonce:';

export interface RecoverAccountConfirmInput {
  /** path param ':token' */
  readonly approval_url_token: string;
  /** Path the request hit (e.g. '/api/agent-auth/recover-account-confirm/abc'). */
  readonly path: string;
  /** Method must match what's signed (POST). */
  readonly method: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly raw_body: Buffer | string;
}

export interface RecoverAccountConfirmDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly internal_secret: Buffer;
  /** Required for SPEC §2.9 finalize-on-approve: when /callback
   *  deferred key issuance because owner_approval was pending,
   *  /recover-account-confirm needs KMS to issue the deferred key
   *  on 'approved'. SaaSes that don't configure owner_approval can
   *  omit this — the finalize path is gated on the session having
   *  awaiting_identity_id != NULL. */
  readonly kms?: KmsAdapter;
  readonly now?: () => number;
}

export interface RecoverAccountConfirmResponse {
  readonly request_id: string;
  readonly account_id: string;
  readonly decision: 'approved' | 'denied';
  readonly decision_at: string;
}

interface ApprovalRow {
  request_id: string;
  account_id: string;
  poll_token: string;
  approval_url_token: string;
  decision: 'pending' | 'approved' | 'denied' | null;
  decision_at: Date | null;
  expires_at: Date;
}

export async function recoverAccountConfirm(
  input: RecoverAccountConfirmInput,
  deps: RecoverAccountConfirmDeps,
): Promise<RecoverAccountConfirmResponse> {
  // 1. Verify HMAC.
  const verified = verifyInboundOwnerApproval({
    secret: deps.internal_secret,
    method: input.method,
    path: input.path,
    headers: input.headers,
    raw_body: input.raw_body,
    ...(deps.now ? { now: deps.now } : {}),
  });

  // 2. Single-use nonce (RT-19): atomic SET NX EX on Redis. If the key
  //    already exists this is a replay → reject 401. Atomicity is critical
  //    for concurrent requests with the same nonce — a GET-then-SET pair
  //    would have a TOCTOU window between them.
  const nonceKey = NONCE_KEY_PREFIX + verified.nonce;
  const claimed = await deps.redis.setIfNotExists(nonceKey, '1', NONCE_TTL_SECONDS);
  if (!claimed) {
    throw new AgentAuthError(401, 'invalid_request', 'replay detected');
  }

  // 3. Validate body + look up approval row.
  type ConfirmBodyT = z.infer<typeof ConfirmBody>;
  let body: ConfirmBodyT;
  try {
    const json = JSON.parse(
      typeof input.raw_body === 'string' ? input.raw_body : input.raw_body.toString('utf8'),
    ) as unknown;
    const parsed = ConfirmBody.safeParse(json);
    if (!parsed.success) throw new Error('zod');
    body = parsed.data;
  } catch {
    throw new AgentAuthError(400, 'invalid_request', 'invalid body');
  }

  // Wrap the SELECT FOR UPDATE + UPDATE + audit-row write in one txn so
  // (a) the row lock actually holds across the read-modify-write and
  // (b) the audit row commits atomically with the decision (SPEC §6.4).
  return deps.postgres.transaction(async (client) => {
    const sel = await client.query<ApprovalRow>(
      `SELECT request_id::text AS request_id, account_id::text AS account_id,
              poll_token, approval_url_token, decision, decision_at, expires_at
         FROM agent_recovery_approvals
        WHERE approval_url_token = $1
        FOR UPDATE`,
      [input.approval_url_token],
    );
    const row = sel.rows[0];
    if (!row) {
      throw new AgentAuthError(404, 'invalid_request', 'approval not found');
    }
    const now = (deps.now ?? Date.now)();
    if (row.expires_at.getTime() < now) {
      throw new AgentAuthError(410, 'session_expired', 'approval expired');
    }
    if (row.decision === 'approved' || row.decision === 'denied') {
      // Idempotent: return the existing decision (no audit row — already
      // emitted at first decision).
      return {
        request_id: row.request_id,
        account_id: row.account_id,
        decision: row.decision,
        decision_at: (row.decision_at ?? new Date()).toISOString(),
      };
    }
    const upd = await client.query<{ decision_at: Date }>(
      `UPDATE agent_recovery_approvals
          SET decision = $2,
              decision_at = now(),
              decision_reason = $3
        WHERE approval_url_token = $1 AND (decision IS NULL OR decision = 'pending')
        RETURNING decision_at`,
      [input.approval_url_token, body.decision, body.reason ?? null],
    );
    const decision_at = upd.rows[0]?.decision_at ?? new Date();
    await writeAuditRowOnClient(client, {
      event_type: 'recover_account_owner_decision',
      endpoint: '/api/agent-auth/recover-account-confirm',
      status_class: 2,
      account_id: row.account_id,
      meta: {
        request_id: row.request_id,
        decision: body.decision,
        reason: body.reason ?? null,
      },
    });

    // SPEC §2.9 finalize-on-approve: if /callback deferred key
    // issuance because the approval was pending, the session row has
    // `awaiting_identity_id` set and `status='exchanging'`. Now that
    // the owner has decided, we either:
    //   - 'approved': issue the deferred key, seal to client_pubkey,
    //     transition session to 'ready'.
    //   - 'denied':   transition session to 'failed' with the SPEC
    //     reason.
    // If the session is already 'ready' / 'failed' (e.g. /callback ran
    // BEFORE the owner decided and approval was 'approved' or
    // 'denied' — see the deny-gate at the start of /callback), this
    // path is a no-op.
    const sessRes = await client.query<{
      poll_token: string;
      kind: string;
      client_pubkey: Buffer;
      awaiting_identity_id: string | null;
      status: string;
      account_tier: Tier | null;
    }>(
      // FOR UPDATE OF s — Postgres rejects FOR UPDATE on the nullable
      // side of an outer join, so we explicitly scope the lock to the
      // session row.
      `SELECT s.poll_token, s.kind, s.client_pubkey,
              s.awaiting_identity_id::text AS awaiting_identity_id,
              s.status::text AS status,
              a.tier::text AS account_tier
         FROM agent_registration_sessions s
         LEFT JOIN agent_accounts a ON a.id = s.account_id
        WHERE s.poll_token = $1
        FOR UPDATE OF s`,
      [row.poll_token],
    );
    const sess = sessRes.rows[0];
    if (
      sess &&
      sess.status === 'exchanging' &&
      sess.awaiting_identity_id !== null &&
      body.decision === 'approved' &&
      sess.account_tier !== null
    ) {
      if (!deps.kms) {
        throw new AgentAuthError(
          500,
          'internal_error',
          'kms required to finalize deferred recovery — pass deps.kms',
        );
      }
      const issued = await issueNewKey(client, deps.kms, {
        account_id: row.account_id,
        issuing_identity_id: sess.awaiting_identity_id,
        tier: sess.account_tier,
        scopes: ['read', 'self:rotate'],
      });
      const issuedAt = new Date();
      const payload = buildSealedPayload({
        key_bearer: issued.bearer,
        key_id: issued.key_id,
        account_id: row.account_id,
        scopes: issued.scopes,
        tier: issued.tier,
        is_first_key: false,
        issued_at: issuedAt,
      });
      const ciphertext = seal(payload, sess.client_pubkey);
      await client.query(
        `UPDATE agent_registration_sessions
            SET status = 'ready', result_ciphertext = $2,
                awaiting_identity_id = NULL
          WHERE poll_token = $1 AND status = 'exchanging'`,
        [row.poll_token, ciphertext],
      );
      await writeAuditRowOnClient(client, {
        event_type: 'recover_finalized_after_owner_approval',
        endpoint: '/api/agent-auth/recover-account-confirm',
        status_class: 2,
        account_id: row.account_id,
        key_id: issued.key_id,
        identity_id: sess.awaiting_identity_id,
        meta: {
          request_id: row.request_id,
        },
      });
    } else if (
      sess &&
      sess.status === 'exchanging' &&
      sess.awaiting_identity_id !== null &&
      body.decision === 'denied'
    ) {
      // Owner denied a deferred-recovery session — fail it.
      await client.query(
        `UPDATE agent_registration_sessions
            SET status = 'failed', status_message = 'owner_denied_recovery',
                awaiting_identity_id = NULL
          WHERE poll_token = $1 AND status = 'exchanging'`,
        [row.poll_token],
      );
    }

    return {
      request_id: row.request_id,
      account_id: row.account_id,
      decision: body.decision,
      decision_at: decision_at.toISOString(),
    };
  });
}
