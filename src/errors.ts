/**
 * Error hierarchy for agent-auth.
 *
 * Public errors are JSON-shaped per SPEC §10.3:
 *   { error: { code, message, request_id, documentation_url } }
 *
 * The `code` is a machine-readable enum from §10.4. Add new codes to
 * `AgentAuthErrorCode` and keep the union exhaustive — `assertNever` in
 * downstream switches will catch missed branches at compile time.
 */

export type AgentAuthErrorCode =
  // 400
  | 'invalid_request'
  | 'invalid_provider'
  | 'invalid_label'
  | 'invalid_intent'
  | 'invalid_client_pubkey'
  | 'invalid_poll_token'
  | 'missing_account_id_for_intent'
  // 401
  | 'invalid_key'
  | 'key_revoked'
  | 'key_rotated'
  | 'account_suspended'
  | 'identity_revoked'
  | 'rotation_grace_expired'
  | 'key_expired'
  | 'revalidation_required'
  | 'invalid_secret'
  | 'key_not_found'
  // 403
  | 'insufficient_scope'
  | 'account_suspended_unsuspend_first'
  | 'identity_account_mismatch'
  | 'identity_blocked'
  // 404
  | 'account_not_found'
  | 'identity_not_recognized_for_account'
  // 409
  | 'already_rotating'
  | 'already_revoked'
  | 'account_exists'
  | 'idempotency_mismatch'
  | 'idempotency_key_payload_mismatch'
  | 'identity_blocked_admin_unblock_required'
  | 'identity_blocked_use_recover'
  // 410
  | 'account_closed'
  | 'session_expired'
  | 'invalid_kind'
  | 'already_consumed'
  // 425
  | 'idempotency_in_flight'
  // 429
  | 'too_many_requests'
  | 'too_many_registrations'
  // 500
  | 'internal_error'
  // 503
  | 'durability_unconfirmed'
  | 'durability_unavailable'
  | 'audit_unavailable'
  | 'idp_circuit_open'
  | 'region_replication_stale'
  | 'failover_in_progress'
  | 'idempotency_unknown_outcome'
  | 'idempotency_manual_required';

export interface AgentAuthErrorOptions {
  /** Optional details merged into the error body (scrubbed by §6.6). */
  readonly details?: Readonly<Record<string, unknown>>;
  /** Optional request_id; if absent, route layer fills from X-Request-Id. */
  readonly request_id?: string;
  /** Optional documentation_url override; defaults to config-supplied base. */
  readonly documentation_url?: string;
  /** Wraps an underlying cause without exposing it on the wire. */
  readonly cause?: unknown;
  /** Headers to attach to the response (e.g. Retry-After, WWW-Authenticate). */
  readonly headers?: Readonly<Record<string, string>>;
}

export class AgentAuthError extends Error {
  readonly status: number;
  readonly code: AgentAuthErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly request_id?: string;
  readonly documentation_url?: string;
  readonly headers?: Readonly<Record<string, string>>;

  constructor(
    status: number,
    code: AgentAuthErrorCode,
    message?: string,
    options: AgentAuthErrorOptions = {},
  ) {
    super(message ?? code, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'AgentAuthError';
    this.status = status;
    this.code = code;
    if (options.details !== undefined) this.details = options.details;
    if (options.request_id !== undefined) this.request_id = options.request_id;
    if (options.documentation_url !== undefined) {
      this.documentation_url = options.documentation_url;
    }
    if (options.headers !== undefined) this.headers = options.headers;
  }

  /**
   * Wire format per SPEC §10.3. Do NOT include `details` automatically —
   * route layer decides whether `details` are safe to surface (some are
   * internal-only, such as the audit alert reason).
   */
  toJSON(): {
    error: {
      code: AgentAuthErrorCode;
      message: string;
      request_id?: string;
      documentation_url?: string;
      details?: Readonly<Record<string, unknown>>;
    };
  } {
    const error: {
      code: AgentAuthErrorCode;
      message: string;
      request_id?: string;
      documentation_url?: string;
      details?: Readonly<Record<string, unknown>>;
    } = { code: this.code, message: this.message };
    if (this.request_id) error.request_id = this.request_id;
    if (this.documentation_url) error.documentation_url = this.documentation_url;
    if (this.details) error.details = this.details;
    return { error };
  }
}

/**
 * 503 family. Thrown on durability/availability faults — the lib will retry
 * idempotent operations (with a fresh Idempotency-Key) and let mutations
 * surface this to the caller (so they can decide retry vs page).
 */
export class ServiceUnavailableError extends AgentAuthError {
  constructor(
    code: Extract<
      AgentAuthErrorCode,
      | 'durability_unconfirmed'
      | 'durability_unavailable'
      | 'audit_unavailable'
      | 'idp_circuit_open'
      | 'region_replication_stale'
      | 'failover_in_progress'
      | 'idempotency_unknown_outcome'
      | 'idempotency_manual_required'
    >,
    message?: string,
    options: AgentAuthErrorOptions = {},
  ) {
    super(503, code, message, options);
    this.name = 'ServiceUnavailableError';
  }
}

/** Convenience factory used inside validateKey() to keep call sites short. */
export function reject(
  status: number,
  code: AgentAuthErrorCode,
  options: AgentAuthErrorOptions = {},
): never {
  throw new AgentAuthError(status, code, undefined, options);
}

/** Exhaustiveness helper — fails the build if a switch misses a branch. */
export function assertNever(x: never): never {
  throw new Error(`unreachable: ${JSON.stringify(x)}`);
}

/** Type guard for catch blocks. */
export function isAgentAuthError(err: unknown): err is AgentAuthError {
  return err instanceof AgentAuthError;
}
