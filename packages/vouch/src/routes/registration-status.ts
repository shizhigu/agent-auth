/**
 * POST /api/agent-auth/registration-status (and the recover-account-status
 * variant). SPEC §10.1.
 *
 * The poll_token PK has a kind-binding CHECK constraint server-side
 * (§3.6 poll_token_prefix_matches_kind). The handler additionally
 * validates the kind matches the endpoint variant (RT-21 session-fixation
 * defense): a `pkr_*` token cannot be polled at /registration-status.
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { SessionKind } from '../types.js';

export type RegistrationStatusEndpoint = 'registration' | 'recover' | 'add_key' | 'revalidate';

const STATUS_BODY = z.object({ poll_token: z.string().min(1) }).strict();

export type RegistrationStatusResponse =
  | { readonly status: 'pending' }
  | {
      readonly status: 'completed';
      readonly account_id: string;
      /**
       * Sealed-box payload (base64url) carrying the freshly issued key.
       * SPEC §2.4: for kind='revalidate' (poll_token prefix `pav_`), no
       * new key is issued — the field is `null` and the agent retries
       * its original request with its EXISTING bearer.
       *
       * **Single-use:** the first poll that returns this transitions the
       * session to status='claimed' atomically. Subsequent polls return
       * `{ status: 'claimed' }` (see below). Stolen poll_tokens still
       * can't decrypt the payload (it's bound to the original
       * `client_pubkey`), but this prevents an attacker from harvesting
       * the ciphertext for offline analysis or future-day attacks.
       */
      readonly encrypted_payload: string | null;
      readonly is_first_key: boolean;
    }
  | {
      /**
       * The session was completed and the encrypted_payload was already
       * delivered. Legitimate clients hold their key; subsequent polls
       * are either (a) a retry that arrived after the first succeeded
       * — clients should ignore — or (b) someone with a leaked
       * poll_token, which can't decrypt the original payload anyway.
       */
      readonly status: 'claimed';
      readonly account_id: string;
    }
  | {
      readonly status: 'failed';
      readonly code: string;
      readonly message: string;
    };

export interface RegistrationStatusDeps {
  readonly postgres: PostgresAdapter;
  /** The endpoint variant — different routes accept different kinds. */
  readonly endpoint: RegistrationStatusEndpoint;
  /** Override 'now' for tests. Defaults to Date.now. */
  readonly now?: () => number;
}

// SPEC §10.1: /registration-status accepts both `pak_` (register) and
// `pad_` (add_key) tokens. /recover-account-status accepts only `pkr_`.
// The 'add_key' / 'revalidate' endpoint variants are kept for SaaSes
// that want a stricter single-kind mount for those flows; the default
// /registration-status mount uses 'registration' and gets both kinds
// per SPEC.
const ENDPOINT_TO_KINDS: Record<RegistrationStatusEndpoint, ReadonlyArray<SessionKind>> = {
  registration: ['register', 'add_key'],
  recover: ['recover'],
  add_key: ['add_key'],
  revalidate: ['revalidate'],
};

const PREFIX_TO_KIND: Record<string, SessionKind> = {
  pak_: 'register',
  pkr_: 'recover',
  pad_: 'add_key',
  pav_: 'revalidate',
};

function pollTokenKind(token: string): SessionKind | null {
  const prefix = token.slice(0, 4);
  return PREFIX_TO_KIND[prefix] ?? null;
}

export async function registrationStatus(
  rawBody: unknown,
  deps: RegistrationStatusDeps,
): Promise<RegistrationStatusResponse> {
  const parsed = STATUS_BODY.safeParse(rawBody);
  if (!parsed.success) throw new AgentAuthError(400, 'invalid_poll_token');

  const tokenKind = pollTokenKind(parsed.data.poll_token);
  if (tokenKind === null) throw new AgentAuthError(400, 'invalid_poll_token');

  const expectedKinds = ENDPOINT_TO_KINDS[deps.endpoint];
  if (!expectedKinds.includes(tokenKind)) {
    // RT-21: do not accept a recovery token at the registration endpoint.
    throw new AgentAuthError(410, 'invalid_kind');
  }

  return deps.postgres.withClient(async (client) => {
    // SELECT FOR UPDATE so the ready -> claimed transition is atomic
    // even if two pollers race. The row-level lock holds for the rest
    // of this transaction.
    const { rows } = await client.query<{
      kind: SessionKind;
      account_id: string | null;
      status: string;
      status_message: string | null;
      result_ciphertext: Buffer | null;
      expires_at: Date;
    }>(
      `SELECT kind, account_id, status, status_message,
              result_ciphertext, expires_at
         FROM agent_registration_sessions
        WHERE poll_token = $1
        FOR UPDATE`,
      [parsed.data.poll_token],
    );
    const row = rows[0];
    if (!row) throw new AgentAuthError(410, 'session_expired');

    const now = (deps.now ?? Date.now)();
    if (row.expires_at.getTime() < now && row.status !== 'ready') {
      throw new AgentAuthError(410, 'session_expired');
    }

    if (row.status === 'pending' || row.status === 'exchanging') {
      return { status: 'pending' as const };
    }

    if (row.status === 'failed') {
      return {
        status: 'failed' as const,
        code: row.status_message ?? 'failed',
        message: row.status_message ?? 'registration failed',
      };
    }

    if (row.status === 'expired') {
      throw new AgentAuthError(410, 'session_expired');
    }

    // 'claimed' — payload was already delivered once. Don't return it
    // again. Stolen poll_tokens can't decrypt the (now-deleted)
    // ciphertext anyway, but this stops them from harvesting it.
    if (row.status === 'claimed') {
      if (!row.account_id) throw new AgentAuthError(500, 'internal_error');
      return { status: 'claimed' as const, account_id: row.account_id };
    }

    // status === 'ready' — first claim wins.
    if (!row.account_id) {
      throw new AgentAuthError(500, 'internal_error');
    }
    if (row.kind !== 'revalidate' && !row.result_ciphertext) {
      throw new AgentAuthError(500, 'internal_error');
    }

    const captured_payload = row.result_ciphertext;

    // Atomic ready -> claimed transition; NULL the ciphertext (the
    // 0007 CHECK constraint enforces this).
    await client.query(
      `UPDATE agent_registration_sessions
          SET status = 'claimed',
              result_ciphertext = NULL
        WHERE poll_token = $1
          AND status = 'ready'`,
      [parsed.data.poll_token],
    );

    return {
      status: 'completed' as const,
      account_id: row.account_id,
      encrypted_payload: captured_payload
        ? captured_payload.toString('base64url')
        : null,
      is_first_key: deriveIsFirstKey(row.kind),
    };
  });
}

/**
 * is_first_key is logically a property of the issuance event. It's
 * encoded redundantly in the sealed payload (§2.6) and surfaced here
 * for SaaS UX. v0.1: true only for kind='register'; others (recover /
 * add_key / revalidate) are false.
 */
function deriveIsFirstKey(kind: SessionKind): boolean {
  return kind === 'register';
}
