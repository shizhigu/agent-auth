/**
 * GoogleProvider — Google / Google Workspace OAuth2 + OIDC. Thin wrapper
 * over OidcProvider with Google's discovery URL hardcoded and a few
 * Google-specific knobs (hosted-domain restriction).
 *
 * Use with a single Gmail account, a Google Workspace tenant, or
 * unrestricted public OAuth.
 */

import { OidcProvider, type Fetcher } from '../oidc/provider.js';
import type { AssuranceLevel, IdentityProvider } from '../../types.js';

export interface GoogleProviderConfig {
  /** OAuth client_id from https://console.cloud.google.com/apis/credentials. */
  readonly client_id: string;
  /** OAuth client_secret. KMS-managed in production. */
  readonly client_secret: string;
  /**
   * If set, restricts authentication to a single Google Workspace domain
   * (e.g. `acme.com`). Google enforces this server-side via the `hd`
   * authorize-URL param and returns `hd` in the userinfo response. The
   * SaaS should additionally check `attestation.raw_metadata.hd`
   * matches.
   */
  readonly hosted_domain?: string;
  /** OAuth scopes; default `openid email profile`. */
  readonly scopes?: ReadonlyArray<string>;
  /** Default assurance level reported in Attestation. Default 'medium'. */
  readonly default_assurance?: AssuranceLevel;
  /** Override stable provider name (used in audit + IdentityProvider.name). Default `google`. */
  readonly name?: string;
  /** Injectable HTTP client for tests. Defaults to global fetch. */
  readonly fetcher?: Fetcher;
}

const GOOGLE_ISSUER = 'https://accounts.google.com';

export class GoogleProvider implements IdentityProvider {
  readonly name: string;
  private readonly inner: OidcProvider;

  constructor(cfg: GoogleProviderConfig) {
    this.name = cfg.name ?? 'google';
    this.inner = new OidcProvider({
      name: this.name,
      client_id: cfg.client_id,
      client_secret: cfg.client_secret,
      issuer_url: GOOGLE_ISSUER,
      ...(cfg.scopes ? { scopes: cfg.scopes } : {}),
      ...(cfg.default_assurance ? { default_assurance: cfg.default_assurance } : {}),
      ...(cfg.fetcher ? { fetcher: cfg.fetcher } : {}),
      extra_authorize_params: {
        ...(cfg.hosted_domain ? { hd: cfg.hosted_domain } : {}),
        // Google requires `access_type=offline` to get a refresh token,
        // but we don't store one — drop it.
      },
    });
  }

  beginRegistration(ctx: Parameters<IdentityProvider['beginRegistration']>[0]) {
    return this.inner.beginRegistration(ctx);
  }

  exchangeOrVerify(
    input: Parameters<IdentityProvider['exchangeOrVerify']>[0],
    ctx: Parameters<IdentityProvider['exchangeOrVerify']>[1],
  ) {
    return this.inner.exchangeOrVerify(input, ctx);
  }

  revalidate(args: Parameters<IdentityProvider['revalidate']>[0]) {
    return this.inner.revalidate(args);
  }
}
