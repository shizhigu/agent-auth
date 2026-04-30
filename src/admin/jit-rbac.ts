/**
 * Just-in-time RBAC for admin operations. SPEC §8.1 (admin.jit_rbac).
 *
 * Idea: an admin doesn't carry the `agent_auth_admin` role permanently —
 * they request a time-bounded grant through the CLI, which records an
 * auditable row and emits a Postgres GRANT (or — when the lib's role
 * model is used as-is — issues an in-process signed token the lib's
 * runtime checks at request time).
 *
 * v0.1: in-process model. The lib stores grants in memory keyed by
 * (admin_id, role); each grant has (granted_at, expires_at, audit_id,
 * approval_signature). The admin-CLI middleware checks `assertGrant()`
 * before dispatching a destructive command.
 */

import { randomUUID } from 'node:crypto';
import { AgentAuthError } from '../errors.js';

export interface JitGrant {
  readonly grant_id: string;
  readonly admin_id: string;
  readonly role: 'agent_auth_admin' | 'agent_auth_readonly' | 'agent_auth_app';
  readonly granted_at: number; // ms epoch
  readonly expires_at: number; // ms epoch
  readonly reason: string;
  /** Optional JSON metadata captured at grant time (e.g. ticket id). */
  readonly metadata?: Record<string, unknown>;
}

export interface JitRbacOptions {
  /** Default TTL in seconds. Default 3600 (1h) per §8.1. */
  readonly default_ttl_seconds?: number;
  /** Max TTL admins can request. Default 4h. */
  readonly max_ttl_seconds?: number;
  /** Now for tests. */
  readonly now?: () => number;
  /** Optional audit hook; called on grant + revoke. */
  readonly onAudit?: (event: { kind: 'granted' | 'revoked'; grant: JitGrant }) => void;
}

export class JitRbac {
  private grants = new Map<string, JitGrant>();
  private readonly default_ttl_ms: number;
  private readonly max_ttl_ms: number;
  private readonly now: () => number;
  private readonly onAudit?: JitRbacOptions['onAudit'];

  constructor(opts: JitRbacOptions = {}) {
    this.default_ttl_ms = (opts.default_ttl_seconds ?? 3600) * 1000;
    this.max_ttl_ms = (opts.max_ttl_seconds ?? 4 * 3600) * 1000;
    this.now = opts.now ?? Date.now;
    if (opts.onAudit) this.onAudit = opts.onAudit;
  }

  grant(args: {
    admin_id: string;
    role: JitGrant['role'];
    reason: string;
    ttl_seconds?: number;
    metadata?: Record<string, unknown>;
  }): JitGrant {
    if (!args.reason || args.reason.length < 8) {
      throw new AgentAuthError(400, 'invalid_request', 'reason required (≥8 chars)');
    }
    // Defense in depth (SPEC §8.1): non-finite or non-positive
    // ttl_seconds must be rejected. NaN slips past `Math.min` and
    // makes expires_at = NaN; subsequent `expires_at <= now()` checks
    // are always false (NaN comparisons), producing an effectively-
    // immortal grant — bypassing the 4h cap entirely. Infinity caps
    // safely but we reject for clarity, and ≤0 produces an immediately-
    // dead grant which is a UX footgun.
    if (args.ttl_seconds !== undefined) {
      if (!Number.isFinite(args.ttl_seconds) || args.ttl_seconds <= 0) {
        throw new AgentAuthError(
          400,
          'invalid_request',
          'ttl_seconds must be a positive finite number',
        );
      }
    }
    const ttl_ms = Math.min(
      this.max_ttl_ms,
      (args.ttl_seconds ?? this.default_ttl_ms / 1000) * 1000,
    );
    const granted_at = this.now();
    const grant: JitGrant = {
      grant_id: randomUUID(),
      admin_id: args.admin_id,
      role: args.role,
      granted_at,
      expires_at: granted_at + ttl_ms,
      reason: args.reason,
      ...(args.metadata !== undefined ? { metadata: args.metadata } : {}),
    };
    this.grants.set(grant.grant_id, grant);
    this.onAudit?.({ kind: 'granted', grant });
    return grant;
  }

  /** Check that the supplied grant_id is alive for the requested role. */
  assertGrant(grant_id: string, role: JitGrant['role']): JitGrant {
    const g = this.grants.get(grant_id);
    if (!g) {
      throw new AgentAuthError(401, 'invalid_request', 'jit_grant_not_found');
    }
    if (g.role !== role) {
      throw new AgentAuthError(403, 'insufficient_scope', 'jit_grant_role_mismatch');
    }
    if (g.expires_at <= this.now()) {
      this.grants.delete(grant_id);
      throw new AgentAuthError(401, 'invalid_request', 'jit_grant_expired');
    }
    return g;
  }

  revoke(grant_id: string): void {
    const g = this.grants.get(grant_id);
    if (!g) return;
    this.grants.delete(grant_id);
    this.onAudit?.({ kind: 'revoked', grant: g });
  }

  /** Test introspection. */
  size(): number {
    return this.grants.size;
  }
}
