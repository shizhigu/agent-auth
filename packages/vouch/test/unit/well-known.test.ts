/**
 * Unit: GET /.well-known/agent-auth (SPEC §10.1).
 *
 *   - shape: matches the §10.1 keys exactly (version, endpoints, supported_providers,
 *     available_scopes, rate_limit_headers, registration_max_age_seconds,
 *     min_revocation_latency_seconds, barrier_mode, documentation_url)
 *   - endpoints prefix the SaaS base_url with /api/agent-auth/<route>
 *   - supported_providers reflects each registered provider, with overrides
 *   - barrier_mode translates 'strict_uncached' verbatim and bounded_stale to 'bounded_stale_<n>s'
 *   - trailing slash on base_url is normalized away
 */
import { describe, it, expect } from 'vitest';
import { wellKnown } from '../../src/routes/well-known.js';
import type { Attestation, IdentityProvider, ParsedWebhook } from '../../src/types.js';

class StubProvider implements IdentityProvider {
  constructor(public readonly name: string) {}
  async beginRegistration() {
    return {};
  }
  async exchangeOrVerify(): Promise<Attestation> {
    throw new Error('not used');
  }
  async revalidate() {
    return { still_valid: true };
  }
  async handleWebhook(): Promise<ParsedWebhook> {
    return { event_id: '', event_type: '', actions: [] };
  }
}

describe('wellKnown (SPEC §10.1)', () => {
  it('produces the SPEC-shaped body for strict_uncached mode', () => {
    const body = wellKnown({
      base_url: 'https://saas.com',
      identity_providers: [new StubProvider('github_app')],
      barrier_mode: 'strict_uncached',
    });
    expect(body.version).toBe('v1');
    expect(body.endpoints).toEqual({
      begin_registration: 'https://saas.com/api/agent-auth/begin-registration',
      registration_status: 'https://saas.com/api/agent-auth/registration-status',
      rotate_key: 'https://saas.com/api/agent-auth/rotate-key',
      revoke: 'https://saas.com/api/agent-auth/revoke',
      recover_account: 'https://saas.com/api/agent-auth/recover-account',
    });
    expect(body.supported_providers).toEqual([
      {
        name: 'github_app',
        supports_browser_flow: true,
        supports_device_flow: false,
        default_assurance: 'medium',
      },
    ]);
    expect(body.available_scopes).toEqual([
      'read',
      'write',
      'admin:keys',
      'self:rotate',
      'self:revoke',
    ]);
    expect(body.rate_limit_headers).toEqual({
      remaining: 'X-RateLimit-Remaining',
      reset: 'X-RateLimit-Reset',
      limit: 'X-RateLimit-Limit',
      retry_after: 'Retry-After',
    });
    expect(body.registration_max_age_seconds).toBe(300);
    expect(body.min_revocation_latency_seconds).toBe(100);
    expect(body.barrier_mode).toBe('strict_uncached');
    expect(body.documentation_url).toBe('https://saas.com/docs/agent-auth');
  });

  it('translates bounded_stale ValidationMode to "bounded_stale_<n>s"', () => {
    const body = wellKnown({
      base_url: 'https://saas.com',
      identity_providers: [new StubProvider('github_app')],
      barrier_mode: { kind: 'bounded_stale', bounded_stale_ms: 1000 },
    });
    expect(body.barrier_mode).toBe('bounded_stale_1s');
    const body3 = wellKnown({
      base_url: 'https://saas.com',
      identity_providers: [new StubProvider('github_app')],
      barrier_mode: { kind: 'bounded_stale', bounded_stale_ms: 3000 },
    });
    expect(body3.barrier_mode).toBe('bounded_stale_3s');
  });

  it('honors per-provider capability overrides', () => {
    const body = wellKnown({
      base_url: 'https://saas.com',
      identity_providers: [
        new StubProvider('github_app'),
        new StubProvider('custom_idp'),
      ],
      provider_capabilities: {
        github_app: {
          supports_browser_flow: true,
          supports_device_flow: true, // override default false
          default_assurance: 'high',
        },
      },
      barrier_mode: 'strict_uncached',
    });
    const ghp = body.supported_providers.find((p) => p.name === 'github_app')!;
    const custom = body.supported_providers.find((p) => p.name === 'custom_idp')!;
    expect(ghp.supports_device_flow).toBe(true);
    expect(ghp.default_assurance).toBe('high');
    // Defaults for unconfigured provider.
    expect(custom.supports_browser_flow).toBe(true);
    expect(custom.supports_device_flow).toBe(false);
    expect(custom.default_assurance).toBe('medium');
  });

  it('strips trailing slashes from base_url', () => {
    const body = wellKnown({
      base_url: 'https://saas.com///',
      identity_providers: [new StubProvider('github_app')],
      barrier_mode: 'strict_uncached',
    });
    expect(body.endpoints.begin_registration).toBe(
      'https://saas.com/api/agent-auth/begin-registration',
    );
    expect(body.documentation_url).toBe('https://saas.com/docs/agent-auth');
  });

  it('available_scopes + documentation_url overrides take precedence', () => {
    const body = wellKnown({
      base_url: 'https://saas.com',
      identity_providers: [new StubProvider('github_app')],
      barrier_mode: 'strict_uncached',
      available_scopes: ['read', 'admin:keys'],
      documentation_url: 'https://docs.example.com/agent-auth',
    });
    expect(body.available_scopes).toEqual(['read', 'admin:keys']);
    expect(body.documentation_url).toBe('https://docs.example.com/agent-auth');
  });
});
