/**
 * Shared domain types for agent-auth. Mirrors SPEC.md Part III (data layer)
 * and Part II (identity protocol). Keep enum string unions in sync with the
 * SQL `*_enum` domains in schema/migrations/0001_init.sql.
 */

export type Tier = 'cold' | 'warm' | 'hot';
export type AccountStatus = 'active' | 'suspended' | 'closed';
export type IdentityStatus = 'active' | 'revoked' | 'expired';
export type AssuranceLevel = 'low' | 'medium' | 'high';
export type RotationState = 'active' | 'rotating' | 'rotated' | 'revoked';
export type RevocationSource =
  | 'webhook'
  | 'expiry'
  | 'manual'
  | 'cascade'
  | 'admin';
export type SessionStatus =
  | 'pending'
  | 'exchanging'
  | 'ready'
  | 'failed'
  | 'expired';
export type SessionKind = 'register' | 'recover' | 'add_key' | 'revalidate';
export type IdempotencyState =
  | 'pending'
  | 'completed'
  | 'failed'
  | 'unknown'
  | 'manual_required';

/**
 * KeyCache: data needed to validate a key without round-tripping Postgres.
 * Populated by validateKey() (§5.3.3) and replicated to Redis + local LRU.
 *
 * SPEC.md §5.3.1 is the source of truth for the cache layout.
 */
export interface KeyCache {
  readonly key_id: string;
  readonly account_id: string;
  readonly account_status: AccountStatus;
  readonly issuing_identity_id: string;
  readonly issuing_identity_status: IdentityStatus;
  readonly identity_provider: string;
  readonly identity_subject: string;
  readonly identity_display_handle?: string;
  readonly identity_assurance_level: AssuranceLevel;
  readonly key_hash: Buffer;
  readonly key_pepper_version: number;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: Tier;
  readonly rotation_state: RotationState;
  readonly revoked_at: string | null;
  readonly grace_expires_at: string | null;
  readonly expires_at: string | null;
  readonly cached_epoch: number;
  readonly cached_at: number; // ms since epoch
  readonly redis_expires_at: number; // ms since epoch
}

/**
 * AgentContext: the only authentication state visible to a SaaS route handler
 * after our middleware runs. Frozen, scope helpers do not mutate it.
 *
 * Per SPEC §6.3 (confused-deputy prevention), this MUST be exposed as
 * `req.agent` (NOT `req.user`) — see ESLint rule in .eslintrc.cjs.
 */
export interface AgentContext {
  readonly account_id: string;
  readonly key_id: string;
  readonly identity: Readonly<{
    provider: string;
    subject: string;
    display_handle?: string;
    assurance_level: AssuranceLevel;
  }>;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: Tier;
  has_scope(scope: string): boolean;
  /** Throws AgentAuthError(403, 'insufficient_scope') if missing. */
  require_scope(scope: string): void;
}

/**
 * AttestationContext — passed to IdentityProvider.beginRegistration()
 * (SPEC §2.1). Lib enforces invariants (audience match, nonce single-use,
 * client_pubkey bound, intent immutable).
 */
export interface AttestationContext {
  readonly audience: string;
  readonly nonce: string;
  readonly poll_token: string;
  readonly client_pubkey: Uint8Array;
  readonly ip_hash: Buffer;
  readonly user_agent: string;
  readonly redirect_uri: string;
  readonly pkce_challenge: string;
  readonly pkce_challenge_method: 'S256';
  readonly intent: 'register' | 'recover' | 'add_key' | 'revalidate';
  readonly target_account_id?: string;
}

export interface Attestation {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly expires_at?: Date;
  readonly display_handle?: string;
  readonly assurance_level: AssuranceLevel;
  readonly supports_revalidation: boolean;
  readonly raw_metadata?: Record<string, unknown>;
}

export type ProviderInput =
  | {
      readonly kind: 'oauth_code';
      readonly code: string;
      readonly redirect_uri: string;
      readonly pkce_verifier: string;
    }
  | { readonly kind: 'attestation_jwt'; readonly token: string }
  | { readonly kind: 'api_key'; readonly key: string }
  | { readonly kind: 'device_code'; readonly device_code: string };

export interface BeginRegistrationResult {
  readonly challenge_url?: string;
  readonly deep_link?: string;
  readonly device_code_info?: {
    readonly user_code: string;
    readonly verification_uri: string;
    readonly verification_uri_complete?: string;
    readonly expires_in_seconds: number;
    readonly poll_interval_seconds: number;
  };
}

export type WebhookAction =
  | {
      readonly type: 'revoke_identity';
      readonly subject: string;
      readonly reason: string;
    }
  | {
      readonly type: 'flag_identity';
      readonly subject: string;
      readonly signal: string;
    };

export interface ParsedWebhook {
  readonly event_id: string;
  readonly event_type: string;
  readonly actions: ReadonlyArray<WebhookAction>;
}

export interface IdentityProvider {
  readonly name: string;
  beginRegistration(ctx: AttestationContext): Promise<BeginRegistrationResult>;
  exchangeOrVerify(
    input: ProviderInput,
    ctx: AttestationContext,
  ): Promise<Attestation>;
  revalidate(identity: {
    provider: string;
    subject: string;
    audience: string;
  }): Promise<{
    still_valid: boolean;
    new_assurance_level?: AssuranceLevel;
  }>;
  handleWebhook?(
    headers: Record<string, string>,
    raw_body: Buffer,
  ): Promise<ParsedWebhook>;
}

/**
 * Pseudo-clock injectable for tests. Real production code uses Date.now() /
 * new Date() through a singleton instance of `RealClock`.
 */
export interface Clock {
  now(): Date;
  monoNowMs(): number;
}

export class RealClock implements Clock {
  now(): Date {
    return new Date();
  }
  monoNowMs(): number {
    return Date.now();
  }
}
