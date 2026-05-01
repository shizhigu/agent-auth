/**
 * OidcProvider — generic OpenID Connect Authorization Code + PKCE flow.
 *
 * Works against any standards-compliant OIDC IdP (Google Workspace,
 * Microsoft Entra, Okta, Auth0, Keycloak, Ory Hydra, ZITADEL, ...). Two
 * modes for endpoint discovery:
 *
 *   1. Auto-discover via `issuer_url` — the constructor fetches
 *      `${issuer_url}/.well-known/openid-configuration` lazily on first
 *      use and caches the result.
 *   2. Manual config — pass `endpoints: { authorization, token, userinfo }`
 *      directly. Skips discovery entirely. Useful for testing or for
 *      IdPs that don't ship a discovery doc.
 *
 * Lifecycle:
 *
 *   - beginRegistration: builds the authorize URL with state=nonce +
 *     code_challenge + scope (defaults to `openid email profile`).
 *   - exchangeOrVerify: POST to token endpoint, then GET userinfo to
 *     extract the canonical `sub`. We do NOT verify the id_token JWT in
 *     v0 — the access_token round-trip to userinfo over HTTPS gives us
 *     equivalent assurance, and skipping JWT verification avoids
 *     bundling JWKS handling. Documented limitation.
 *   - revalidate: returns { still_valid: true } unconditionally. Real
 *     revalidation requires a stored refresh_token or an admin API
 *     key, neither of which is in scope for v0 — SaaS apps that need
 *     stricter revalidation can override the provider.
 *
 * Threats covered:
 *   - RT-29: state binds the authorize URL to the session row; PKCE S256
 *     binds the token exchange. The lib enforces single-use at /callback.
 *   - RT-31: returns Attestation.audience = ctx.audience so the lib's
 *     identity-account binding check fires for cross-tenant recovery.
 */

import type {
  AssuranceLevel,
  Attestation,
  AttestationContext,
  BeginRegistrationResult,
  IdentityProvider,
  ProviderInput,
} from '../../types.js';
import { AgentAuthError } from '../../errors.js';

export type Fetcher = typeof fetch;

export interface OidcEndpoints {
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
}

export interface OidcProviderConfig {
  /** Stable provider name surfaced as Attestation.issuer + IdentityProvider.name. */
  readonly name: string;
  /** OAuth client_id registered at the IdP. */
  readonly client_id: string;
  /** OAuth client_secret. KMS-managed in production. */
  readonly client_secret: string;
  /**
   * Either `issuer_url` (for auto-discovery) or `endpoints` (manual).
   * Exactly one must be set.
   */
  readonly issuer_url?: string;
  readonly endpoints?: OidcEndpoints;
  /** OAuth scopes; default `openid email profile`. */
  readonly scopes?: ReadonlyArray<string>;
  /** Default assurance level reported in Attestation. Default 'medium'. */
  readonly default_assurance?: AssuranceLevel;
  /** Extra query params to append to the authorize URL. */
  readonly extra_authorize_params?: Readonly<Record<string, string>>;
  /** Injectable HTTP client. Defaults to global fetch. */
  readonly fetcher?: Fetcher;
}

interface DiscoveryDoc {
  readonly issuer: string;
  readonly authorization_endpoint: string;
  readonly token_endpoint: string;
  readonly userinfo_endpoint: string;
}

interface UserinfoResponse {
  readonly sub: string;
  readonly email?: string;
  readonly email_verified?: boolean;
  readonly name?: string;
  readonly preferred_username?: string;
  readonly picture?: string;
  readonly hd?: string;
}

interface TokenResponse {
  readonly access_token?: string;
  readonly token_type?: string;
  readonly expires_in?: number;
  readonly id_token?: string;
  readonly refresh_token?: string;
  readonly scope?: string;
  readonly error?: string;
  readonly error_description?: string;
}

const DEFAULT_SCOPES = ['openid', 'email', 'profile'] as const;

export class OidcProvider implements IdentityProvider {
  readonly name: string;
  private readonly cfg: OidcProviderConfig;
  private readonly fetcher: Fetcher;
  private endpoints: OidcEndpoints | null;
  private discoveryPromise: Promise<OidcEndpoints> | null = null;

  constructor(cfg: OidcProviderConfig) {
    if (!cfg.issuer_url && !cfg.endpoints) {
      throw new Error('OidcProvider: provide either issuer_url or endpoints');
    }
    if (cfg.issuer_url && cfg.endpoints) {
      throw new Error('OidcProvider: provide ONE of issuer_url or endpoints, not both');
    }
    if (!cfg.client_id || !cfg.client_secret) {
      throw new Error('OidcProvider: client_id and client_secret are required');
    }
    if (!/^[a-z0-9_-]+$/i.test(cfg.name)) {
      throw new Error(`OidcProvider: invalid name "${cfg.name}" (alnum + _- only)`);
    }
    this.name = cfg.name;
    this.cfg = cfg;
    this.fetcher = cfg.fetcher ?? fetch;
    this.endpoints = cfg.endpoints ?? null;
  }

  async beginRegistration(ctx: AttestationContext): Promise<BeginRegistrationResult> {
    const ep = await this.resolveEndpoints();
    const scopes = (this.cfg.scopes ?? DEFAULT_SCOPES).join(' ');
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.cfg.client_id,
      redirect_uri: ctx.redirect_uri,
      scope: scopes,
      state: ctx.nonce,
      code_challenge: ctx.pkce_challenge,
      code_challenge_method: 'S256',
    });
    if (this.cfg.extra_authorize_params) {
      for (const [k, v] of Object.entries(this.cfg.extra_authorize_params)) {
        params.set(k, v);
      }
    }
    return { challenge_url: `${ep.authorization_endpoint}?${params.toString()}` };
  }

  async exchangeOrVerify(
    input: ProviderInput,
    ctx: AttestationContext,
  ): Promise<Attestation> {
    if (input.kind !== 'oauth_code') {
      throw new AgentAuthError(
        400,
        'invalid_request',
        `OidcProvider only supports oauth_code, got ${input.kind}`,
      );
    }
    const ep = await this.resolveEndpoints();

    // Step 1: token exchange (POST application/x-www-form-urlencoded).
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: input.code,
      redirect_uri: input.redirect_uri,
      code_verifier: input.pkce_verifier,
      client_id: this.cfg.client_id,
      client_secret: this.cfg.client_secret,
    });
    const tokRes = await this.fetcher(ep.token_endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
      },
      body: body.toString(),
    });
    let tok: TokenResponse;
    try {
      tok = (await tokRes.json()) as TokenResponse;
    } catch (err) {
      throw new AgentAuthError(
        502,
        'invalid_request',
        'token endpoint returned non-JSON',
        { cause: err },
      );
    }
    if (!tokRes.ok || tok.error || !tok.access_token) {
      throw new AgentAuthError(
        401,
        'invalid_request',
        `token exchange failed: ${tok.error ?? `HTTP ${tokRes.status}`}` +
          (tok.error_description ? ` — ${tok.error_description}` : ''),
      );
    }

    // Step 2: userinfo (canonical sub). We trust this over the id_token
    // because we just fetched it over HTTPS using the freshly-minted
    // access_token; the IdP's TLS provides equivalent integrity.
    const userRes = await this.fetcher(ep.userinfo_endpoint, {
      headers: {
        authorization: `Bearer ${tok.access_token}`,
        accept: 'application/json',
      },
    });
    if (!userRes.ok) {
      throw new AgentAuthError(
        401,
        'invalid_request',
        `userinfo fetch failed: HTTP ${userRes.status}`,
      );
    }
    const user = (await userRes.json()) as UserinfoResponse;
    if (!user.sub) {
      throw new AgentAuthError(401, 'invalid_request', 'userinfo response missing `sub`');
    }

    // Drop the access_token. The lib will store the Attestation; the
    // bearer token never sees Postgres.
    const meta: Record<string, unknown> = { sub: user.sub };
    if (user.email !== undefined) meta['email'] = user.email;
    if (user.email_verified !== undefined) meta['email_verified'] = user.email_verified;
    if (user.preferred_username !== undefined) meta['preferred_username'] = user.preferred_username;
    if (user.hd !== undefined) meta['hd'] = user.hd;

    return {
      issuer: this.name,
      subject: user.sub,
      audience: ctx.audience,
      assurance_level: this.cfg.default_assurance ?? 'medium',
      supports_revalidation: false,
      ...(user.name ? { display_handle: user.name } : {}),
      raw_metadata: meta,
    };
  }

  // The IdentityProvider contract takes an `identity` arg (provider /
  // subject / audience). We don't use it in v0 — real revalidation
  // requires a stored refresh_token or admin API key, neither of which
  // is in scope. SaaSes that need stricter revalidation can subclass.
  async revalidate(_identity: {
    provider: string;
    subject: string;
    audience: string;
  }): Promise<{ still_valid: boolean }> {
    return { still_valid: true };
  }

  // -----------------------------------------------------------------------
  // Discovery
  // -----------------------------------------------------------------------

  private async resolveEndpoints(): Promise<OidcEndpoints> {
    if (this.endpoints) return this.endpoints;
    if (!this.discoveryPromise) {
      this.discoveryPromise = (async () => {
        const issuer = this.cfg.issuer_url!.replace(/\/+$/, '');
        const url = `${issuer}/.well-known/openid-configuration`;
        const res = await this.fetcher(url);
        if (!res.ok) {
          this.discoveryPromise = null;
          throw new AgentAuthError(
            502,
            'invalid_request',
            `OIDC discovery failed: ${url} -> HTTP ${res.status}`,
          );
        }
        const doc = (await res.json()) as DiscoveryDoc;
        if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.userinfo_endpoint) {
          this.discoveryPromise = null;
          throw new AgentAuthError(
            502,
            'invalid_request',
            `OIDC discovery doc missing required endpoints (issuer=${issuer})`,
          );
        }
        this.endpoints = {
          authorization_endpoint: doc.authorization_endpoint,
          token_endpoint: doc.token_endpoint,
          userinfo_endpoint: doc.userinfo_endpoint,
        };
        return this.endpoints;
      })();
    }
    return this.discoveryPromise;
  }
}
