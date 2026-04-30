/**
 * DemoStubProvider — auto-approving identity provider for the local demo.
 *
 * In production you'd plug in `GitHubAppProvider` (or a future
 * Google / GitLab / OIDC provider). Those need real OAuth credentials and
 * a browser to click "Authorize" — too much setup for a 5-minute demo.
 *
 * This stub:
 *   - returns a `challenge_url` pointing at the SaaS's own /__demo/auto-approve
 *     route, which immediately redirects to /agent-auth/callback (mirrors what
 *     a real IdP would do after the human clicks Authorize)
 *   - accepts any `code` on exchangeOrVerify and returns a deterministic
 *     Attestation derived from the session nonce, so each registration is a
 *     fresh "user"
 *   - revalidate always succeeds — the demo doesn't exercise revalidation
 *
 * It does NOT implement webhooks; the demo skips revocation cascades.
 */
import type {
  IdentityProvider,
  AttestationContext,
  Attestation,
  ProviderInput,
  BeginRegistrationResult,
} from 'agent-auth';

export interface DemoStubProviderConfig {
  /** Where /__demo/auto-approve lives on the SaaS, e.g. http://localhost:3000/__demo/auto-approve */
  readonly autoApproveBaseUrl: string;
}

export class DemoStubProvider implements IdentityProvider {
  readonly name = 'demo-stub';

  constructor(private readonly cfg: DemoStubProviderConfig) {}

  async beginRegistration(ctx: AttestationContext): Promise<BeginRegistrationResult> {
    const params = new URLSearchParams({
      state: ctx.nonce,
      redirect_uri: ctx.redirect_uri,
    });
    return { challenge_url: `${this.cfg.autoApproveBaseUrl}?${params.toString()}` };
  }

  async exchangeOrVerify(
    input: ProviderInput,
    ctx: AttestationContext,
  ): Promise<Attestation> {
    if (input.kind !== 'oauth_code') {
      throw new Error(`demo stub only handles oauth_code, got ${input.kind}`);
    }
    // The demo doesn't validate the code — any value is accepted. A real
    // provider would exchange it against the IdP.
    return {
      issuer: 'demo-stub',
      subject: `demo-user-${ctx.nonce.slice(0, 8)}`,
      audience: ctx.audience,
      assurance_level: 'medium',
      supports_revalidation: true,
      display_handle: 'demo-user',
    };
  }

  async revalidate(): Promise<{ still_valid: boolean }> {
    return { still_valid: true };
  }
}
