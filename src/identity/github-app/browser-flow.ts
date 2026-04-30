/**
 * GitHubAppProvider — implements `IdentityProvider` for GitHub App auth
 * (default, primary v0.1 provider). SPEC §2.2.
 *
 * Three lifecycle methods:
 *   - beginRegistration: builds the OAuth authorize URL (browser flow)
 *   - exchangeOrVerify:  exchanges the code for an access_token, fetches
 *                        /user, drops the access_token, returns Attestation
 *   - revalidate:        App-JWT-authenticated /user/{id} GET to confirm
 *                        the upstream identity still resolves
 *
 * Threats covered:
 *   - RT-29 (state/challenge phishing): state=nonce + PKCE S256 both bound
 *     to the session row; the lib enforces single-use at /callback.
 *   - RT-31 (recovery confused-deputy): the `audience` field on the
 *     resulting Attestation must match `ctx.audience`; the lib (callback
 *     handler) checks identity-account binding.
 *
 * The provider does NOT touch Postgres; that lives in the callback route
 * so the provider stays pluggable.
 *
 * `fetcher` defaults to global `fetch` but is injectable for tests so we
 * never have to mock the network.
 */

import type {
  AttestationContext,
  Attestation,
  AssuranceLevel,
  BeginRegistrationResult,
  IdentityProvider,
  ParsedWebhook,
  ProviderInput,
} from '../../types.js';
import { AgentAuthError } from '../../errors.js';

export type Fetcher = typeof fetch;

export interface GitHubAppProviderConfig {
  /** GitHub App Client ID (e.g. `Iv1.abcdef`). */
  readonly client_id: string;
  /** GitHub App client secret (KMS-managed). */
  readonly client_secret: string;
  /** Webhook signing secret (current). */
  readonly webhook_secret?: string;
  /** Optional previous webhook secret accepted alongside `webhook_secret`
   *  during a rotation window per RT-42. */
  readonly webhook_secret_previous?: string;
  /** App private key PEM for App-JWT (revalidate + webhook replay polling). */
  readonly app_private_key_pem?: string;
  /** Default assurance level reported in Attestation (§2.2.1). */
  readonly default_assurance?: AssuranceLevel;
  /** GitHub API version header. */
  readonly api_version?: string;
  /** OAuth scopes; default ['read:user']. */
  readonly scopes?: ReadonlyArray<string>;
  /** Injectable HTTP client. Defaults to global fetch. */
  readonly fetcher?: Fetcher;
  /** Override for test/local: GitHub OAuth host. Default github.com. */
  readonly github_host?: string;
  /** Override for test/local: GitHub API host. Default api.github.com. */
  readonly github_api_host?: string;
}

interface GitHubAccessTokenResponse {
  readonly access_token?: string;
  readonly token_type?: string;
  readonly scope?: string;
  readonly error?: string;
  readonly error_description?: string;
}

interface GitHubUserResponse {
  readonly id: number;
  readonly login: string;
  readonly name?: string | null;
  readonly type?: string;
}

export class GitHubAppProvider implements IdentityProvider {
  readonly name = 'github_app';
  private readonly fetcher: Fetcher;
  private readonly githubHost: string;
  private readonly githubApiHost: string;
  private readonly apiVersion: string;
  private readonly scopes: ReadonlyArray<string>;
  private readonly defaultAssurance: AssuranceLevel;

  constructor(private readonly cfg: GitHubAppProviderConfig) {
    this.fetcher = cfg.fetcher ?? fetch;
    this.githubHost = cfg.github_host ?? 'https://github.com';
    this.githubApiHost = cfg.github_api_host ?? 'https://api.github.com';
    this.apiVersion = cfg.api_version ?? '2022-11-28';
    this.scopes = cfg.scopes ?? ['read:user'];
    this.defaultAssurance = cfg.default_assurance ?? 'medium';
  }

  async beginRegistration(ctx: AttestationContext): Promise<BeginRegistrationResult> {
    const params = new URLSearchParams({
      client_id: this.cfg.client_id,
      redirect_uri: ctx.redirect_uri,
      state: ctx.nonce,
      code_challenge: ctx.pkce_challenge,
      code_challenge_method: 'S256',
      response_type: 'code',
      scope: this.scopes.join(' '),
      // Audience binding (defense in depth — GitHub already binds tokens to client_id)
      // We do NOT include `login` / `allow_signup` / etc. — those are SaaS UX choices.
    });
    return {
      challenge_url: `${this.githubHost}/login/oauth/authorize?${params.toString()}`,
    };
  }

  async exchangeOrVerify(
    input: ProviderInput,
    ctx: AttestationContext,
  ): Promise<Attestation> {
    if (input.kind !== 'oauth_code') {
      throw new AgentAuthError(400, 'invalid_request', 'github_app expects oauth_code input');
    }
    if (input.redirect_uri !== ctx.redirect_uri) {
      // The callback handler should already enforce this, but we double-check
      // so the provider cannot be misused independently.
      throw new AgentAuthError(400, 'invalid_request', 'redirect_uri mismatch');
    }

    // 1. Exchange auth_code for access_token (this is the audience binding —
    //    GitHub bound the auth_code to our client_id at /authorize).
    const tokenResp = await this.fetcher(`${this.githubHost}/login/oauth/access_token`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'User-Agent': 'agent-auth/0.1',
      },
      body: JSON.stringify({
        client_id: this.cfg.client_id,
        client_secret: this.cfg.client_secret,
        code: input.code,
        redirect_uri: input.redirect_uri,
        code_verifier: input.pkce_verifier,
      }),
    });

    if (!tokenResp.ok) {
      throw new AgentAuthError(400, 'invalid_request', `github_token_exchange_failed: ${tokenResp.status}`);
    }
    const tokenJson = (await tokenResp.json()) as GitHubAccessTokenResponse;
    if (tokenJson.error || !tokenJson.access_token) {
      // GitHub returns 200 with { error, error_description } for things like
      // bad_verification_code, redirect_uri_mismatch, etc.
      throw new AgentAuthError(
        400,
        'invalid_request',
        `github_oauth_error: ${tokenJson.error ?? 'no_token'}`,
      );
    }
    const access_token = tokenJson.access_token;

    // 2. Fetch /user so we have the durable numeric subject.
    const userResp = await this.fetcher(`${this.githubApiHost}/user`, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': this.apiVersion,
        Authorization: `Bearer ${access_token}`,
        'User-Agent': 'agent-auth/0.1',
      },
    });
    if (!userResp.ok) {
      throw new AgentAuthError(400, 'invalid_request', `github_user_fetch_failed: ${userResp.status}`);
    }
    const user = (await userResp.json()) as GitHubUserResponse;
    if (typeof user.id !== 'number' || typeof user.login !== 'string') {
      throw new AgentAuthError(400, 'invalid_request', 'github_user_unexpected_shape');
    }

    // 3. Drop access_token (we never store it). The Attestation captures the
    //    durable identity only.
    return {
      issuer: 'github.com',
      subject: String(user.id),
      audience: this.cfg.client_id,
      display_handle: user.login,
      assurance_level: this.defaultAssurance,
      supports_revalidation: true,
      raw_metadata: { type: user.type ?? 'User' },
    };
  }

  async revalidate(identity: {
    provider: string;
    subject: string;
    audience: string;
  }): Promise<{ still_valid: boolean; new_assurance_level?: AssuranceLevel }> {
    if (identity.provider !== this.name) {
      return { still_valid: false };
    }
    if (identity.audience !== this.cfg.client_id) {
      // Audience drift means SaaS rotated their GitHub App; treat as invalid.
      return { still_valid: false };
    }
    // Use the App JWT to look up the user by id. We do NOT store an
    // installation token — App JWT is enough for /user/{id}.
    if (!this.cfg.app_private_key_pem) {
      // Without an App key configured, we cannot revalidate; report still_valid
      // so revalidation is a no-op rather than a false positive denial.
      return { still_valid: true };
    }
    // Build the App JWT lazily so callers without a key don't pay the cost.
    const jwt = await buildAppJwt(this.cfg.client_id, this.cfg.app_private_key_pem);
    const resp = await this.fetcher(`${this.githubApiHost}/user/${encodeURIComponent(identity.subject)}`, {
      method: 'GET',
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': this.apiVersion,
        Authorization: `Bearer ${jwt}`,
        'User-Agent': 'agent-auth/0.1',
      },
    });
    if (resp.status === 404) return { still_valid: false };
    if (!resp.ok) {
      // Treat transient errors as still-valid; the circuit breaker (M5)
      // will pause revalidation if upstream is flaky.
      return { still_valid: true };
    }
    return { still_valid: true, new_assurance_level: this.defaultAssurance };
  }

  async handleWebhook(
    headers: Record<string, string>,
    raw_body: Buffer,
  ): Promise<ParsedWebhook> {
    if (!this.cfg.webhook_secret) {
      throw new AgentAuthError(500, 'internal_error', 'webhook_secret_not_configured');
    }
    const sig = lookupHeader(headers, 'x-hub-signature-256');
    const event_type = lookupHeader(headers, 'x-github-event');
    const delivery = lookupHeader(headers, 'x-github-delivery');
    if (!sig || !event_type || !delivery) {
      throw new AgentAuthError(400, 'invalid_request', 'missing_webhook_headers');
    }

    // RT-42: dual-secret rotation window. Accept either current or previous
    // webhook secret; constant-time compare of the hex digest.
    const candidates: string[] = [this.cfg.webhook_secret];
    if (this.cfg.webhook_secret_previous) {
      candidates.push(this.cfg.webhook_secret_previous);
    }
    const ok = candidates.some((s) => verifyGithubSignature(raw_body, sig, s));
    if (!ok) {
      throw new AgentAuthError(401, 'invalid_request', 'invalid_signature');
    }

    let parsed: GitHubWebhookPayload;
    try {
      parsed = JSON.parse(raw_body.toString('utf8')) as GitHubWebhookPayload;
    } catch {
      throw new AgentAuthError(400, 'invalid_request', 'invalid_json');
    }

    const actions: WebhookAction[] = [];
    if (
      event_type === 'github_app_authorization' &&
      parsed.action === 'revoked' &&
      parsed.sender?.id !== undefined
    ) {
      actions.push({
        type: 'revoke_identity',
        subject: String(parsed.sender.id),
        reason: 'user_revoked_app_access',
      });
    }
    return {
      event_id: delivery,
      event_type,
      actions,
    };
  }
}

interface GitHubWebhookPayload {
  readonly action?: string;
  readonly sender?: { readonly id?: number; readonly login?: string };
}

function lookupHeader(headers: Record<string, string>, name: string): string | undefined {
  // Case-insensitive lookup. Most Node frameworks already lowercase header keys
  // but we don't trust callers to normalize.
  const lc = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lc) return v;
  }
  return undefined;
}

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { WebhookAction } from '../../types.js';

function verifyGithubSignature(body: Buffer, header_value: string, secret: string): boolean {
  // GitHub format: 'sha256=<hex>'.
  const m = /^sha256=([0-9a-f]{64})$/.exec(header_value.trim());
  if (!m) return false;
  const expected = m[1]!;
  const computed = createHmac('sha256', secret).update(body).digest('hex');
  if (computed.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(expected, 'hex'));
}

// ---------------------------------------------------------------------------
// App JWT (RS256). Implemented inline to avoid pulling jsonwebtoken — the
// App JWT format is small and we only need to sign one claim type.
// ---------------------------------------------------------------------------

import { createSign } from 'node:crypto';

async function buildAppJwt(client_id: string, pem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iat: now - 60,         // GitHub guidance: backdate a minute for clock skew
    exp: now + 9 * 60,     // 10-minute max; we use 9 to leave headroom
    iss: client_id,
  };
  const headerB64 = base64url(Buffer.from(JSON.stringify(header)));
  const payloadB64 = base64url(Buffer.from(JSON.stringify(payload)));
  const signing_input = `${headerB64}.${payloadB64}`;
  const signer = createSign('RSA-SHA256');
  signer.update(signing_input);
  const sig = signer.sign(pem);
  return `${signing_input}.${base64url(sig)}`;
}

function base64url(b: Buffer): string {
  return b.toString('base64url');
}
