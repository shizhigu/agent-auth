/**
 * POST /api/agent-auth/webhooks/:provider — framework-agnostic handler.
 * SPEC §2.2.4.
 *
 * Order matters (RT-6 / RT-30):
 *   1. provider.handleWebhook performs HMAC verify FIRST and only returns
 *      ParsedWebhook on success (anything else throws AgentAuthError).
 *   2. Atomic dedup INSERT keyed on X-GitHub-Delivery (PK) — does not run
 *      until the body is verified, so attackers cannot poison the dedup
 *      table with bogus (id, payload) pairs.
 *   3. If duplicate delivery and the body hash matches the stored one,
 *      return 200 (idempotent no-op). Body-hash mismatch raises an alert
 *      but the existing row wins.
 *   4. Apply WebhookActions inside a Tier B transaction:
 *        - revoke_identity → cascade revoke active+rotating keys, suspend
 *          account if no other primary identity active, bump epoch,
 *          append revocation_log.
 *   5. Mark agent_webhook_events.status='processed', return 200.
 *   6. Post-commit barrier capture + cache invalidation (best-effort).
 */

import { createHash } from 'node:crypto';
import { AgentAuthError, isAgentAuthError } from '../errors.js';
import {
  bumpEpochInTx,
} from '../distributed/revocation-epoch.js';
import { captureBarrierAfterCommit } from '../distributed/revocation-barrier.js';
import { invalidateKey } from '../distributed/cache-invalidation.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import type {
  IdentityProvider,
  ParsedWebhook,
  WebhookAction,
} from '../types.js';

export interface WebhookInput {
  readonly provider: string; // ':provider' from URL
  readonly headers: Record<string, string>;
  readonly raw_body: Buffer;
}

export interface WebhookDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly identity_providers: ReadonlyArray<IdentityProvider>;
  readonly region: string;
  /** Optional alerting hook for RT-30 X-GitHub-Delivery payload-mismatch. */
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface WebhookResult {
  readonly status: 'processed' | 'duplicate' | 'ignored';
  readonly invalidated_keys: ReadonlyArray<string>;
}

const ROW_FOR_KEY = ['key_id', 'account_id', 'issued_via_identity_id'] as const;

interface ExistingEvent {
  payload_hash: Buffer;
  status: string;
}

interface KeyRow {
  id: string;
  key_id: string;
  account_id: string;
}

interface IdentityRow {
  id: string;
  account_id: string;
  status: string;
}

export async function handleWebhookRequest(
  input: WebhookInput,
  deps: WebhookDeps,
): Promise<WebhookResult> {
  const provider = deps.identity_providers.find((p) => p.name === input.provider);
  if (!provider || !provider.handleWebhook) {
    // Anti-enumeration: never disclose unknown vs unsupported.
    throw new AgentAuthError(404, 'invalid_request', 'unknown_provider');
  }

  // Step 1: verify + parse. Throws on signature failure / malformed body.
  let parsed: ParsedWebhook;
  try {
    parsed = await provider.handleWebhook(input.headers, input.raw_body);
  } catch (err) {
    if (isAgentAuthError(err)) throw err;
    throw new AgentAuthError(400, 'invalid_request', 'webhook_verify_failed', { cause: err });
  }

  const payload_hash = createHash('sha256').update(input.raw_body).digest();

  // Step 2-3: atomic dedup INSERT.
  const insertRes = await deps.postgres.query<{ inserted: boolean }>(
    `INSERT INTO agent_webhook_events (id, provider, event_type, payload_hash, status)
     VALUES ($1::uuid, $2, $3, $4, 'received')
     ON CONFLICT (id) DO NOTHING
     RETURNING (xmax = 0) AS inserted`,
    [parsed.event_id, provider.name, parsed.event_type, payload_hash],
  );
  const inserted = insertRes.rows[0]?.inserted === true;

  if (!inserted) {
    const existing = await deps.postgres.queryOne<ExistingEvent>(
      `SELECT payload_hash, status FROM agent_webhook_events WHERE id = $1::uuid`,
      [parsed.event_id],
    );
    if (existing) {
      const existingHash = Buffer.isBuffer(existing.payload_hash)
        ? existing.payload_hash
        : Buffer.from(existing.payload_hash);
      if (!existingHash.equals(payload_hash)) {
        deps.onAlert?.('webhook_id_collision_with_payload_mismatch', {
          delivery_id: parsed.event_id,
          provider: provider.name,
        });
      }
    }
    return { status: 'duplicate', invalidated_keys: [] };
  }

  // Step 4: apply actions in a single transaction.
  let invalidated_keys: string[] = [];
  try {
    await deps.postgres.transaction(async (client) => {
      await client.query("SET LOCAL synchronous_commit = 'remote_apply'");
      for (const action of parsed.actions) {
        const out = await applyAction(action, provider.name, client, deps);
        invalidated_keys = invalidated_keys.concat(out);
      }
      await client.query(
        `UPDATE agent_webhook_events
            SET status = 'processed', processed_at = now()
          WHERE id = $1::uuid`,
        [parsed.event_id],
      );
    });
  } catch (err) {
    await deps.postgres
      .query(
        `UPDATE agent_webhook_events
            SET status = 'failed', error = $2, processed_at = now()
          WHERE id = $1::uuid`,
        [parsed.event_id, errorMessage(err).slice(0, 500)],
      )
      .catch(() => undefined);
    throw err;
  }

  // Step 6: post-commit barrier + Redis invalidations.
  if (invalidated_keys.length > 0) {
    try {
      await captureBarrierAfterCommit(deps.postgres);
    } catch {
      /* swallow */
    }
    for (const kid of invalidated_keys) {
      // We don't know account_id without re-fetching; pass undefined so the
      // SREM is skipped. The reconciler in §5.3.6 closes any drift in the
      // account-keys SET.
      await invalidateKey(deps.redis, kid);
    }
  }

  return {
    status: parsed.actions.length > 0 ? 'processed' : 'ignored',
    invalidated_keys,
  };
}

async function applyAction(
  action: WebhookAction,
  provider_name: string,
  client: import('pg').PoolClient,
  deps: WebhookDeps,
): Promise<string[]> {
  if (action.type === 'flag_identity') {
    // v0.1: just record in audit log; risk-score adjustment lives in M5.
    return [];
  }
  // revoke_identity
  // 1. Find the identity row by (provider, subject, audience). Audience is
  //    the configured client_id; provider supplies it on construction. We
  //    lookup by provider+subject+ANY-audience for now — agent_identities
  //    has UNIQUE on (provider, subject, audience), and a single GitHub
  //    App produces a single audience. If a SaaS rotates audiences, all
  //    identities under the previous audience are still findable here.
  const idRes = await client.query<IdentityRow>(
    `SELECT id, account_id, status FROM agent_identities
      WHERE provider = $1 AND subject = $2 AND status = 'active'
      FOR UPDATE`,
    [provider_name, action.subject],
  );
  const idRow = idRes.rows[0];
  if (!idRow) {
    // Already revoked or never existed; idempotent no-op.
    return [];
  }
  await client.query(
    `UPDATE agent_identities
        SET status = 'revoked',
            revoked_at = now(),
            revoked_reason = $2,
            revocation_source = 'webhook'
      WHERE id = $1`,
    [idRow.id, action.reason],
  );
  // 2. Cascade revoke keys.
  const keysRes = await client.query<KeyRow>(
    `UPDATE agent_api_keys
        SET rotation_state = 'revoked',
            revoked_at = now(),
            revoked_reason = 'primary_identity_revoked'
      WHERE issued_via_identity_id = $1
        AND rotation_state IN ('active', 'rotating')
      RETURNING ${ROW_FOR_KEY.join(', ')}`,
    [idRow.id],
  );
  const keys = keysRes.rows.map((r) => r.key_id);

  // 3. Cascade account suspend if no other primary active identity remains.
  const remainingPrimary = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM agent_identities
      WHERE account_id = $1 AND status = 'active' AND is_primary = true`,
    [idRow.account_id],
  );
  if (Number(remainingPrimary.rows[0]?.count ?? '0') === 0) {
    await client.query(
      `UPDATE agent_accounts
          SET status = 'suspended', suspended_at = now()
        WHERE id = $1 AND status = 'active'`,
      [idRow.account_id],
    );
  }

  // 4. Bump epoch + append revocation_log.
  const { epoch } = await bumpEpochInTx(client, deps.redis);
  const lsn = await client.query<{ commit_lsn: string }>(
    `SELECT pg_current_wal_insert_lsn()::text AS commit_lsn`,
  );
  const commit_lsn = lsn.rows[0]?.commit_lsn ?? '0/0';
  await client.query(
    `INSERT INTO agent_revocation_log
       (region, kind, target_id, commit_lsn, epoch, reason)
     VALUES ($1, 'identity_revoke', $2, $3::pg_lsn, $4, $5)`,
    [deps.region, action.subject, commit_lsn, epoch, action.reason],
  );
  return keys;
}

function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return 'unknown_error';
}
