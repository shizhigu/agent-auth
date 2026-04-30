/**
 * POST /api/agent-auth/begin-registration handler (framework-agnostic).
 *
 * SPEC §10.1 + §2.2.2 + §6.2.1 (RT-29 / RT-31). The handler:
 *   - validates input with zod
 *   - looks up the configured IdentityProvider for `provider`
 *   - builds AttestationContext (nonce, PKCE, client_pubkey, intent…)
 *   - calls provider.beginRegistration(ctx) to get challenge_url / device_code_info
 *   - INSERTs `agent_registration_sessions` row (poll_token PK; the
 *     poll_token-prefix-matches-kind constraint is enforced server-side
 *     by the §3.6 CHECK)
 *   - returns the §10.1 response
 *
 * It intentionally does NOT touch req/res. The Express/Hono adapter
 * marshals input from the request body and writes the JSON output. This
 * matches the rest of the lib's framework-agnostic split (§11.1).
 */

import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { AgentAuthError, ServiceUnavailableError } from '../errors.js';
import { generatePkcePair } from '../crypto/pkce.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import { RegistrationSessionRepo } from '../storage/registration-session-repo.js';
import type {
  AttestationContext,
  IdentityProvider,
  SessionKind,
} from '../types.js';

// ---------------------------------------------------------------------------
// Input validation (§10.1)
// ---------------------------------------------------------------------------

const Intent = z.enum(['register', 'recover', 'add_key', 'revalidate']);

const BeginRegistrationBody = z
  .object({
    provider: z.string().min(1),
    intent: Intent,
    label: z.string().max(64).optional(),
    use_device_flow: z.boolean().optional(),
    client_pubkey: z.string(),
    account_id: z.string().uuid().optional(),
  })
  .strict();

export type BeginRegistrationInput = z.infer<typeof BeginRegistrationBody>;

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

export interface BeginRegistrationResponse {
  readonly poll_token: string;
  readonly expires_at: string;
  readonly poll_interval_seconds: number;
  readonly challenge_url?: string;
  readonly device_code_info?: {
    readonly user_code: string;
    readonly verification_uri: string;
    readonly verification_uri_complete?: string;
    readonly expires_in_seconds: number;
    readonly poll_interval_seconds: number;
  };
}

// ---------------------------------------------------------------------------
// Deps
// ---------------------------------------------------------------------------

export interface BeginRegistrationDeps {
  readonly postgres: PostgresAdapter;
  readonly identity_providers: ReadonlyArray<IdentityProvider>;
  /** Per-provider configured redirect_uri for OAuth callbacks. */
  readonly redirect_uri: (provider: string) => string;
  /** Per-provider audience (e.g. GitHub App client_id). */
  readonly audience: (provider: string) => string;
  /** Pre-built per-IP request context (already rate-limited at middleware). */
  readonly request_context: {
    readonly ip_hash: Buffer;
    readonly user_agent: string;
  };
  /** Now-ish: injectable clock for tests. */
  readonly now?: () => Date;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const POLL_TOKEN_PREFIX: Record<SessionKind, string> = {
  register: 'pak_',
  recover: 'pkr_',
  add_key: 'pad_',
  revalidate: 'pav_',
};

function decodeBase64UrlPubkey(s: string): Buffer {
  let buf: Buffer;
  try {
    buf = Buffer.from(s, 'base64url');
  } catch {
    throw new AgentAuthError(400, 'invalid_client_pubkey');
  }
  if (buf.length !== 32) {
    throw new AgentAuthError(400, 'invalid_client_pubkey');
  }
  return buf;
}

function newPollToken(kind: SessionKind): string {
  return POLL_TOKEN_PREFIX[kind] + randomBytes(32).toString('base64url');
}

function newNonce(): string {
  return randomBytes(32).toString('base64url');
}

function findProvider(
  providers: ReadonlyArray<IdentityProvider>,
  name: string,
): IdentityProvider | null {
  return providers.find((p) => p.name === name) ?? null;
}

function intentToKind(intent: BeginRegistrationInput['intent']): SessionKind {
  // Mapping is 1:1 — kept as a function so future intents (e.g. 'tier_upgrade') stay localized.
  return intent;
}

async function checkAccountForIntent(
  pg: PostgresAdapter,
  account_id: string,
): Promise<void> {
  const row = await pg.queryOne<{ status: string }>(
    `SELECT status FROM agent_accounts WHERE id = $1`,
    [account_id],
  );
  if (!row) throw new AgentAuthError(404, 'account_not_found');
  if (row.status === 'closed') throw new AgentAuthError(410, 'account_closed');
  if (row.status === 'suspended')
    throw new AgentAuthError(403, 'account_suspended_unsuspend_first');
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

const SESSION_TTL_MS = 5 * 60 * 1000;
const POLL_INTERVAL_SECONDS = 2;

export async function beginRegistration(
  rawBody: unknown,
  deps: BeginRegistrationDeps,
): Promise<BeginRegistrationResponse> {
  const parsed = BeginRegistrationBody.safeParse(rawBody);
  if (!parsed.success) {
    // Map zod issues to our error code surface.
    const firstIssue = parsed.error.issues[0];
    if (firstIssue?.path.includes('intent')) {
      throw new AgentAuthError(400, 'invalid_intent');
    }
    if (firstIssue?.path.includes('provider')) {
      throw new AgentAuthError(400, 'invalid_provider');
    }
    if (firstIssue?.path.includes('label')) {
      throw new AgentAuthError(400, 'invalid_label');
    }
    if (firstIssue?.path.includes('client_pubkey')) {
      throw new AgentAuthError(400, 'invalid_client_pubkey');
    }
    throw new AgentAuthError(400, 'invalid_request');
  }

  const body = parsed.data;
  const provider = findProvider(deps.identity_providers, body.provider);
  if (!provider) throw new AgentAuthError(400, 'invalid_provider');

  // Recover / revalidate: account_id is required and must point at a real,
  // non-closed, non-suspended account.
  if (body.intent === 'recover' || body.intent === 'revalidate') {
    if (!body.account_id) {
      throw new AgentAuthError(400, 'missing_account_id_for_intent');
    }
    await checkAccountForIntent(deps.postgres, body.account_id);
  }

  const client_pubkey = decodeBase64UrlPubkey(body.client_pubkey);
  const kind = intentToKind(body.intent);
  const poll_token = newPollToken(kind);
  const nonce = newNonce();
  const pkce = generatePkcePair();
  const audience = deps.audience(provider.name);
  const redirect_uri = deps.redirect_uri(provider.name);
  const now = deps.now ? deps.now() : new Date();
  const expires_at = new Date(now.getTime() + SESSION_TTL_MS);

  const ctx: AttestationContext = {
    audience,
    nonce,
    poll_token,
    client_pubkey,
    ip_hash: deps.request_context.ip_hash,
    user_agent: deps.request_context.user_agent,
    redirect_uri,
    pkce_challenge: pkce.challenge,
    pkce_challenge_method: 'S256',
    intent: body.intent,
    ...(body.account_id !== undefined ? { target_account_id: body.account_id } : {}),
  };

  let providerOut;
  try {
    providerOut = await provider.beginRegistration(ctx);
  } catch (err) {
    // Surface as idp_circuit_open per §10.4. (M5 wires the actual circuit
    // breaker — for now any provider error becomes 503.)
    throw new ServiceUnavailableError('idp_circuit_open', undefined, { cause: err });
  }

  const repo = new RegistrationSessionRepo(deps.postgres);
  await repo.insert({
    poll_token,
    nonce,
    pkce_verifier: pkce.verifier,
    pkce_challenge: pkce.challenge,
    audience,
    expected_provider: provider.name,
    redirect_uri,
    kind,
    ...(body.account_id !== undefined ? { target_account_id: body.account_id } : {}),
    client_pubkey,
    expires_at,
  });

  const out: BeginRegistrationResponse = {
    poll_token,
    expires_at: expires_at.toISOString(),
    poll_interval_seconds:
      providerOut.device_code_info?.poll_interval_seconds ?? POLL_INTERVAL_SECONDS,
    ...(providerOut.challenge_url !== undefined
      ? { challenge_url: providerOut.challenge_url }
      : {}),
    ...(providerOut.device_code_info !== undefined
      ? { device_code_info: providerOut.device_code_info }
      : {}),
  };
  return out;
}
