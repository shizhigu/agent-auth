/**
 * GET /api/agent-auth/callback/:provider — internal OAuth callback. SPEC §2.2.2.
 *
 * The flow (single transaction):
 *   1. Look up `agent_registration_sessions` by nonce (state=, FOR UPDATE).
 *   2. Transition status: pending -> exchanging.
 *   3. Call provider.exchangeOrVerify with the auth_code + PKCE verifier.
 *      Audience binding is enforced by the provider; the resulting
 *      Attestation is what we trust.
 *   4. Locate / create agent_identities row (cases A-D below).
 *   5. issueNewKey() — generate, hash, INSERT.
 *   6. buildSealedPayload + sealed-box encrypt to session.client_pubkey.
 *   7. Transition status -> ready (writes account_id + result_ciphertext).
 *
 * Cases (§2.2.2 step g):
 *   A — no identity row: NEW account. Create account + identity.
 *   B — active row, kind=register: existing account; "additional key" path
 *       (is_first_key=false). Identity must already point at the same
 *       account.
 *   C — revoked, source webhook|expiry, kind=recover: re-activate and
 *       continue (same account_id).
 *   D — revoked, source manual|cascade: 409 identity_blocked_admin_unblock_required.
 *
 * Threats:
 *   - RT-29: state binding. Only `pending` rows match; nonce is single-use
 *     because the session's status moves out of `pending` before we even
 *     call the provider.
 *   - RT-31: tenant confused-deputy in recovery. For kind=recover or
 *     revalidate, target_account_id from session must match the looked-up
 *     identity's account_id.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { KmsAdapter } from '../storage/kms-adapter.js';
import { seal } from '../crypto/sealed-box.js';
import { buildSealedPayload, issueNewKey } from '../identity/issue-key.js';
import { writeAuditRowOnClient } from '../audit/db-writer.js';
import type {
  AssuranceLevel,
  Attestation,
  IdentityProvider,
  RevocationSource,
  SessionKind,
  Tier,
} from '../types.js';

export interface CallbackInput {
  /** Provider name from URL (e.g. ':provider' = 'github_app'). */
  readonly provider: string;
  /** OAuth `state` query param (== session.nonce). */
  readonly state: string;
  /** OAuth `code` query param. */
  readonly code: string;
  /** Optional `error` query param (user-denied flow). */
  readonly error?: string;
  /** Optional `error_description`. */
  readonly error_description?: string;
}

export interface CallbackDeps {
  readonly postgres: PostgresAdapter;
  readonly kms: KmsAdapter;
  readonly identity_providers: ReadonlyArray<IdentityProvider>;
  readonly request_context: { readonly ip_hash: Buffer; readonly user_agent: string };
  readonly now?: () => Date;
}

export interface CallbackOutput {
  /** A simple success URL or HTML the route adapter renders to the browser. */
  readonly status: 'success' | 'failed';
  readonly account_id?: string;
  readonly is_first_key?: boolean;
  /** Reason for status='failed'. */
  readonly reason?: string;
}

interface SessionRow {
  poll_token: string;
  nonce: string;
  pkce_verifier: string;
  pkce_challenge: string;
  audience: string;
  expected_provider: string;
  redirect_uri: string;
  kind: SessionKind;
  target_account_id: string | null;
  client_pubkey: Buffer;
  status: string;
  expires_at: Date;
}

interface IdentityRow {
  id: string;
  account_id: string;
  status: 'active' | 'revoked' | 'expired';
  revocation_source: RevocationSource | null;
}

interface AccountRow {
  id: string;
  status: 'active' | 'suspended' | 'closed';
  tier: Tier;
}

const SUCCESS_KIND_FIRST_KEY = new Set<SessionKind>(['register']);

export async function callback(
  input: CallbackInput,
  deps: CallbackDeps,
): Promise<CallbackOutput> {
  if (input.error) {
    // User denied; mark the session failed if we can identify it. We don't
    // know the poll_token here, only `state`, so we transition by nonce.
    await markFailedByNonce(deps.postgres, input.state, input.error);
    return { status: 'failed', reason: input.error };
  }

  const provider = deps.identity_providers.find((p) => p.name === input.provider);
  if (!provider) {
    // Don't leak whether the provider exists vs the session is missing
    // (anti-enumeration per SPEC §2.2.2 step a).
    return { status: 'failed', reason: 'invalid_callback' };
  }

  const result = await deps.postgres.transaction(async (client) => {
    // 1. Acquire the session row FOR UPDATE.
    const sessRes = await client.query<SessionRow>(
      `SELECT * FROM agent_registration_sessions
        WHERE nonce = $1 AND status = 'pending' AND expires_at > now()
        FOR UPDATE`,
      [input.state],
    );
    const session = sessRes.rows[0];
    if (!session) {
      // RT-21 / RT-29: do not distinguish reasons.
      return { status: 'failed' as const, reason: 'registration_session_not_found_or_expired' };
    }
    if (session.expected_provider !== input.provider) {
      return { status: 'failed' as const, reason: 'provider_mismatch' };
    }

    // 2. Move pending -> exchanging.
    const trans = await client.query(
      `UPDATE agent_registration_sessions
          SET status = 'exchanging'
        WHERE poll_token = $1 AND status = 'pending'`,
      [session.poll_token],
    );
    if (trans.rowCount === 0) {
      return { status: 'failed' as const, reason: 'session_state_race' };
    }

    // 3. Exchange code with provider (outside the row-level lock if it were
    //    long, but fine inline because GitHub responds in <1 RTT typical).
    let attestation: Attestation;
    try {
      attestation = await provider.exchangeOrVerify(
        {
          kind: 'oauth_code',
          code: input.code,
          redirect_uri: session.redirect_uri,
          pkce_verifier: session.pkce_verifier,
        },
        {
          audience: session.audience,
          nonce: session.nonce,
          poll_token: session.poll_token,
          client_pubkey: session.client_pubkey,
          ip_hash: deps.request_context.ip_hash,
          user_agent: deps.request_context.user_agent,
          redirect_uri: session.redirect_uri,
          pkce_challenge: session.pkce_challenge,
          pkce_challenge_method: 'S256',
          intent: session.kind,
          ...(session.target_account_id !== null
            ? { target_account_id: session.target_account_id }
            : {}),
        },
      );
    } catch (err) {
      await client.query(
        `UPDATE agent_registration_sessions
            SET status = 'failed', status_message = $2
          WHERE poll_token = $1`,
        [session.poll_token, errorMessage(err)],
      );
      return { status: 'failed' as const, reason: 'provider_exchange_failed' };
    }

    if (attestation.audience !== session.audience) {
      await client.query(
        `UPDATE agent_registration_sessions
            SET status = 'failed', status_message = 'audience_mismatch'
          WHERE poll_token = $1`,
        [session.poll_token],
      );
      return { status: 'failed' as const, reason: 'audience_mismatch' };
    }

    // 4. Locate / create identity row.
    //
    // Take a transaction-scoped advisory lock keyed on the identity triple
    // BEFORE the SELECT, so concurrent /callback requests for the same
    // (provider, subject, audience) — same human re-clicking, two browser
    // tabs, slow OAuth round-trip — serialize on this row's creation
    // path. Without the lock, T1 and T2 both SELECT no-row, both proceed
    // to Case-A INSERT, and T2 hits the
    // `agent_identities_unique_active` UNIQUE INDEX → SQLSTATE 23505 →
    // txn aborts → opaque 500 to the agent. With the lock, T2 waits for
    // T1's commit, then sees T1's row and falls through to Case B.
    //
    // Hash the triple to a 64-bit key. pg_advisory_xact_lock takes a
    // single bigint; hashtextextended gives 64-bit hash with stable
    // distribution. Released automatically at COMMIT/ROLLBACK.
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
      [`identity:${provider.name}|${attestation.subject}|${attestation.audience}`],
    );
    const idRes = await client.query<IdentityRow>(
      `SELECT id, account_id, status, revocation_source
         FROM agent_identities
        WHERE provider = $1 AND subject = $2 AND audience = $3
        FOR UPDATE`,
      [provider.name, attestation.subject, attestation.audience],
    );
    const idRow = idRes.rows[0];

    let account_id: string;
    let identity_id: string;
    let isFirstKey = false;

    const isRecover = session.kind === 'recover';

    if (!idRow) {
      // Case A — no identity row. New account.
      if (isRecover) {
        // Recovery requires an existing identity to recover; treat as 404.
        await failSession(client, session.poll_token, 'identity_not_recognized_for_account');
        return { status: 'failed' as const, reason: 'identity_not_recognized_for_account' };
      }
      // For revalidate, target_account_id is required and identity should
      // already exist; treat missing as 404 too.
      if (session.kind === 'revalidate') {
        await failSession(client, session.poll_token, 'identity_not_recognized_for_account');
        return { status: 'failed' as const, reason: 'identity_not_recognized_for_account' };
      }
      const newAccount = await client.query<{ id: string; tier: Tier }>(
        `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ($1, 'cold', 'active')
         RETURNING id, tier`,
        [attestation.display_handle ?? null],
      );
      account_id = newAccount.rows[0]!.id;
      const newIdentity = await client.query<{ id: string }>(
        `INSERT INTO agent_identities
           (account_id, provider, subject, audience, issuer, assurance_level,
            display_handle, is_primary, status, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,true,'active',$8)
         RETURNING id`,
        [
          account_id,
          provider.name,
          attestation.subject,
          attestation.audience,
          attestation.issuer,
          attestation.assurance_level,
          attestation.display_handle ?? null,
          attestation.raw_metadata ? JSON.stringify(attestation.raw_metadata) : null,
        ],
      );
      identity_id = newIdentity.rows[0]!.id;
      isFirstKey = SUCCESS_KIND_FIRST_KEY.has(session.kind);
    } else if (idRow.status === 'active') {
      // Case B — active identity row.
      if (
        (isRecover || session.kind === 'revalidate') &&
        session.target_account_id !== null &&
        session.target_account_id !== idRow.account_id
      ) {
        // RT-31: cross-tenant recovery attempt. Fail-closed.
        await failSession(client, session.poll_token, 'identity_account_mismatch');
        return { status: 'failed' as const, reason: 'identity_account_mismatch' };
      }
      account_id = idRow.account_id;
      identity_id = idRow.id;
      isFirstKey = false;
    } else {
      // Revoked.
      if (
        idRow.revocation_source === 'webhook' ||
        idRow.revocation_source === 'expiry'
      ) {
        if (!isRecover) {
          await failSession(client, session.poll_token, 'identity_blocked_use_recover');
          return { status: 'failed' as const, reason: 'identity_blocked_use_recover' };
        }
        // Case C — re-activate.
        await client.query(
          `UPDATE agent_identities
              SET status = 'active', revoked_at = NULL,
                  revoked_reason = NULL, revocation_source = NULL,
                  last_revalidated_at = now()
            WHERE id = $1`,
          [idRow.id],
        );
        account_id = idRow.account_id;
        identity_id = idRow.id;
        isFirstKey = false;
      } else {
        // Case D — manual / cascade revocation. Admin unblock required.
        await failSession(client, session.poll_token, 'identity_blocked_admin_unblock_required');
        return { status: 'failed' as const, reason: 'identity_blocked_admin_unblock_required' };
      }
    }

    // 5. Account status check (re-fetch in case it was just created above).
    const accRes = await client.query<AccountRow>(
      `SELECT id, status, tier FROM agent_accounts WHERE id = $1 FOR UPDATE`,
      [account_id],
    );
    const acc = accRes.rows[0];
    if (!acc) {
      await failSession(client, session.poll_token, 'account_not_found');
      return { status: 'failed' as const, reason: 'account_not_found' };
    }
    if (acc.status === 'closed') {
      await failSession(client, session.poll_token, 'account_closed');
      return { status: 'failed' as const, reason: 'account_closed' };
    }
    if (acc.status === 'suspended') {
      await failSession(client, session.poll_token, 'account_suspended_unsuspend_first');
      return { status: 'failed' as const, reason: 'account_suspended_unsuspend_first' };
    }

    // 5b. SPEC §2.9 owner-approval gate (deny + defer-on-pending).
    //
    // /recover-account inserts an agent_recovery_approvals row with
    // decision='pending' and emits the signed approval webhook. The
    // owner replies via /recover-account-confirm, flipping the
    // decision to 'approved' or 'denied':
    //   - 'denied': fail-closed; never issue the key.
    //   - 'pending': defer issuance — persist the OAuth-verified
    //                identity_id on the session, leave status
    //                'exchanging'. /recover-account-confirm finalizes
    //                the session (issues key + seals + transitions to
    //                'ready') when the owner approves.
    //   - 'approved' | no-row: proceed to issuance (the no-row case
    //     means the SaaS didn't configure owner_approval).
    if (session.kind === 'recover') {
      const apprRes = await client.query<{ decision: string | null }>(
        `SELECT decision FROM agent_recovery_approvals WHERE poll_token = $1`,
        [session.poll_token],
      );
      const decision = apprRes.rows[0]?.decision;
      if (decision === 'denied') {
        await failSession(client, session.poll_token, 'owner_denied_recovery');
        return { status: 'failed' as const, reason: 'owner_denied_recovery' };
      }
      if (decision === 'pending') {
        // Defer: stash the verified identity, leave status 'exchanging'.
        // /recover-account-confirm will finalize on approve.
        await client.query(
          `UPDATE agent_registration_sessions
              SET awaiting_identity_id = $2, account_id = $3
            WHERE poll_token = $1`,
          [session.poll_token, identity_id, account_id],
        );
        await writeAuditRowOnClient(client, {
          event_type: 'recover_callback_deferred_for_owner_approval',
          endpoint: '/api/agent-auth/callback/:provider',
          status_class: 2,
          account_id,
          identity_id,
          meta: {
            provider: provider.name,
            session_kind: session.kind,
          },
        });
        return {
          status: 'success' as const,
          account_id,
          is_first_key: false,
        };
      }
    }

    // 6. SPEC §2.4: kind='revalidate' refreshes last_revalidated_at ONLY
    //    — no new key is issued, no token is stored. The agent retries
    //    its original request with its EXISTING bearer once the session
    //    transitions to 'ready'. Other kinds (register / recover / add_key)
    //    issue + seal a new key.
    if (session.kind === 'revalidate') {
      // last_revalidated_at was already bumped in case-C re-activation
      // (line 280-287). For case-B (active identity, just refresh), do it
      // here in the same txn.
      await client.query(
        `UPDATE agent_identities
            SET last_revalidated_at = now()
          WHERE id = $1`,
        [identity_id],
      );
      // Mark session ready with NO sealed payload — the registration-status
      // response will surface encrypted_payload=null so the SDK knows to
      // retry with the existing key.
      await client.query(
        `UPDATE agent_registration_sessions
            SET status = 'ready', account_id = $2, result_ciphertext = NULL
          WHERE poll_token = $1`,
        [session.poll_token, account_id],
      );
      await writeAuditRowOnClient(client, {
        event_type: 'revalidate_callback_success',
        endpoint: '/api/agent-auth/callback/:provider',
        status_class: 2,
        account_id,
        identity_id,
        meta: {
          provider: provider.name,
          session_kind: session.kind,
        },
      });
      return {
        status: 'success' as const,
        account_id,
        is_first_key: false,
      };
    }

    // Non-revalidate kinds: issue + seal a new key.
    const issued = await issueNewKey(client, deps.kms, {
      account_id,
      issuing_identity_id: identity_id,
      tier: acc.tier,
      scopes: ['read', 'self:rotate'],
    });

    // 7. Build sealed-box payload + finalize session.
    const issuedAt = (deps.now ? deps.now() : new Date());
    const payload = buildSealedPayload({
      key_bearer: issued.bearer,
      key_id: issued.key_id,
      account_id,
      scopes: issued.scopes,
      tier: issued.tier,
      is_first_key: isFirstKey,
      issued_at: issuedAt,
    });
    const ciphertext = seal(payload, session.client_pubkey);

    await client.query(
      `UPDATE agent_registration_sessions
          SET status = 'ready', account_id = $2, result_ciphertext = $3
        WHERE poll_token = $1`,
      [session.poll_token, account_id, ciphertext],
    );

    // SPEC §6.4 — emit audit row in the SAME txn as the account / identity /
    // key creation. event_type tracks the SessionKind for forensics
    // (registration vs recovery vs revalidate produce distinct audit rows).
    await writeAuditRowOnClient(client, {
      event_type: `${session.kind}_callback_success`,
      endpoint: '/api/agent-auth/callback/:provider',
      status_class: 2,
      account_id,
      key_id: issued.key_id,
      identity_id,
      meta: {
        provider: provider.name,
        is_first_key: isFirstKey,
        session_kind: session.kind,
      },
    });

    return {
      status: 'success' as const,
      account_id,
      is_first_key: isFirstKey,
    };
  });

  return result;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async function markFailedByNonce(
  pg: PostgresAdapter,
  nonce: string,
  reason: string,
): Promise<void> {
  await pg.query(
    `UPDATE agent_registration_sessions
        SET status = 'failed', status_message = $2
      WHERE nonce = $1 AND status = 'pending'`,
    [nonce, reason],
  );
}

async function failSession(
  client: { query: (text: string, params?: unknown[]) => Promise<unknown> },
  poll_token: string,
  reason: string,
): Promise<void> {
  await client.query(
    `UPDATE agent_registration_sessions
        SET status = 'failed', status_message = $2
      WHERE poll_token = $1`,
    [poll_token, reason],
  );
}

function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m.slice(0, 200);
  }
  return 'unknown_error';
}

// Re-export for callers that build their own pipelines.
export { Attestation, AssuranceLevel };
