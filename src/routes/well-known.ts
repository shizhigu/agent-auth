/**
 * GET /.well-known/agent-auth — service discovery doc. SPEC §10.1.
 *
 * Static-ish: the JSON is composed once per deploy from the SaaS app
 * config (base URL, identity providers, barrier mode) and served as a
 * cache-friendly response. The lib produces the body; the SaaS app
 * routes it under `/.well-known/agent-auth`.
 *
 * The shape and field names mirror SPEC §10.1 line 3639 exactly so
 * client SDKs can rely on stable keys for v1.
 */

import type { AssuranceLevel, IdentityProvider } from '../types.js';
import type { ValidationMode } from '../config.js';

export interface WellKnownProviderCapability {
  readonly supports_browser_flow: boolean;
  readonly supports_device_flow: boolean;
  readonly default_assurance: AssuranceLevel;
}

export interface WellKnownDeps {
  /** SaaS app's externally-visible base URL, e.g. 'https://saas.com'. */
  readonly base_url: string;
  /** Identity providers the SaaS has wired in (drives `supported_providers[]`). */
  readonly identity_providers: ReadonlyArray<IdentityProvider>;
  /**
   * Per-provider capabilities. Keyed by `provider.name`. If a provider isn't
   * in the map, defaults are used (browser=true, device=false, assurance='medium').
   */
  readonly provider_capabilities?: Readonly<
    Record<string, WellKnownProviderCapability>
  >;
  /** Barrier mode advertised to clients — must match validation.mode. */
  readonly barrier_mode: ValidationMode;
  /** Optional override for the docs URL. */
  readonly documentation_url?: string;
  /** Optional override for the `available_scopes` list. */
  readonly available_scopes?: ReadonlyArray<string>;
  /** Optional override for `registration_max_age_seconds` (default 300). */
  readonly registration_max_age_seconds?: number;
  /** Optional override for `min_revocation_latency_seconds` (default 100). */
  readonly min_revocation_latency_seconds?: number;
}

export interface WellKnownBody {
  readonly version: 'v1';
  readonly endpoints: Readonly<Record<string, string>>;
  readonly supported_providers: ReadonlyArray<{
    readonly name: string;
    readonly supports_browser_flow: boolean;
    readonly supports_device_flow: boolean;
    readonly default_assurance: AssuranceLevel;
  }>;
  readonly available_scopes: ReadonlyArray<string>;
  readonly rate_limit_headers: Readonly<{
    readonly remaining: 'X-RateLimit-Remaining';
    readonly reset: 'X-RateLimit-Reset';
    readonly limit: 'X-RateLimit-Limit';
    readonly retry_after: 'Retry-After';
  }>;
  readonly registration_max_age_seconds: number;
  readonly min_revocation_latency_seconds: number;
  /** SPEC §10.1: 'strict_uncached' or 'bounded_stale_<n>s'. */
  readonly barrier_mode: string;
  readonly documentation_url: string;
}

function describeBarrierMode(mode: ValidationMode): string {
  if (mode === 'strict_uncached') return 'strict_uncached';
  return `bounded_stale_${Math.max(1, Math.round(mode.bounded_stale_ms / 1000))}s`;
}

const DEFAULT_SCOPES = [
  'read',
  'write',
  'admin:keys',
  'self:rotate',
  'self:revoke',
] as const;

const DEFAULT_CAPABILITIES: WellKnownProviderCapability = {
  supports_browser_flow: true,
  supports_device_flow: false,
  default_assurance: 'medium',
};

export function wellKnown(deps: WellKnownDeps): WellKnownBody {
  const base = deps.base_url.replace(/\/+$/, '');
  return {
    version: 'v1',
    endpoints: {
      begin_registration: `${base}/api/agent-auth/begin-registration`,
      registration_status: `${base}/api/agent-auth/registration-status`,
      rotate_key: `${base}/api/agent-auth/rotate-key`,
      revoke: `${base}/api/agent-auth/revoke`,
      recover_account: `${base}/api/agent-auth/recover-account`,
    },
    supported_providers: deps.identity_providers.map((p) => {
      const cap = deps.provider_capabilities?.[p.name] ?? DEFAULT_CAPABILITIES;
      return {
        name: p.name,
        supports_browser_flow: cap.supports_browser_flow,
        supports_device_flow: cap.supports_device_flow,
        default_assurance: cap.default_assurance,
      };
    }),
    available_scopes: deps.available_scopes ?? [...DEFAULT_SCOPES],
    rate_limit_headers: {
      remaining: 'X-RateLimit-Remaining',
      reset: 'X-RateLimit-Reset',
      limit: 'X-RateLimit-Limit',
      retry_after: 'Retry-After',
    },
    registration_max_age_seconds: deps.registration_max_age_seconds ?? 300,
    min_revocation_latency_seconds: deps.min_revocation_latency_seconds ?? 100,
    barrier_mode: describeBarrierMode(deps.barrier_mode),
    documentation_url: deps.documentation_url ?? `${base}/docs/agent-auth`,
  };
}
