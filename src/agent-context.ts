/**
 * AgentContext builder. Mirrors SPEC §6.3 verbatim — frozen object exposed
 * as `req.agent` (NEVER `req.user`) so a SaaS application cannot accidentally
 * mix human-auth and agent-auth contexts.
 *
 * The builder takes a KeyCache (the validated cache snapshot) and produces
 * an immutable AgentContext. `has_scope` / `require_scope` are bound here so
 * downstream code never has to remember to check identity status / rotation
 * state — that already happened in validateKey() before we got here.
 */

import { AgentAuthError } from './errors.js';
import type { AgentContext, KeyCache } from './types.js';

export function buildAgentContext(cache: KeyCache): AgentContext {
  const scopes: ReadonlyArray<string> = Object.freeze([...cache.scopes]);
  const identity = Object.freeze({
    provider: cache.identity_provider,
    subject: cache.identity_subject,
    ...(cache.identity_display_handle !== undefined
      ? { display_handle: cache.identity_display_handle }
      : {}),
    assurance_level: cache.identity_assurance_level,
  });

  const ctx: AgentContext = Object.freeze({
    account_id: cache.account_id,
    key_id: cache.key_id,
    identity,
    scopes,
    tier: cache.tier,
    has_scope(scope: string): boolean {
      return scopes.includes(scope);
    },
    require_scope(scope: string): void {
      if (!scopes.includes(scope)) {
        throw new AgentAuthError(403, 'insufficient_scope', undefined, {
          details: { required: scope },
        });
      }
    },
  });

  return ctx;
}
