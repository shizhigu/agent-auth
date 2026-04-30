/**
 * GET /api/agent-auth/keys — list keys belonging to the caller's account.
 * SPEC §10.1 (Public endpoints).
 *
 * Authorization: requires the caller to hold the `admin:keys` scope.
 * Cross-account guard: even with `admin:keys`, only keys owned by the
 * caller's account are returned (no enumeration outside the tenant).
 *
 * The response shape mirrors §10.1 exactly: a thin projection of
 * `agent_api_keys` plus the account-tier rollup. Revoked keys are
 * excluded from the listing (operators can pull them via the admin CLI).
 */

import { AgentAuthError } from '../errors.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { AgentContext, Tier } from '../types.js';

export interface ListKeysDeps {
  readonly caller: AgentContext;
  readonly postgres: PostgresAdapter;
}

export interface ListedKey {
  readonly key_id: string;
  readonly prefix: string;
  readonly label: string | null;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: Tier;
  readonly rotation_state: string;
  readonly created_at: string;
  readonly last_used_at: string | null;
  readonly expires_at: string | null;
}

export interface ListKeysResponse {
  readonly keys: ReadonlyArray<ListedKey>;
}

const SCOPE_ADMIN_KEYS = 'admin:keys';

interface KeyRow {
  key_id: string;
  prefix: string;
  label: string | null;
  scopes: string[];
  tier: Tier;
  rotation_state: string;
  created_at: Date;
  last_used_at: Date | null;
  expires_at: Date | null;
}

export async function listKeys(deps: ListKeysDeps): Promise<ListKeysResponse> {
  if (!deps.caller.has_scope(SCOPE_ADMIN_KEYS)) {
    throw new AgentAuthError(403, 'insufficient_scope', undefined, {
      details: { required: SCOPE_ADMIN_KEYS },
    });
  }

  const { rows } = await deps.postgres.query<KeyRow>(
    `SELECT key_id, prefix, label, scopes, tier::text AS tier,
            rotation_state::text AS rotation_state,
            created_at, last_used_at, expires_at
       FROM agent_api_keys
      WHERE account_id = $1
        AND rotation_state <> 'revoked'
      ORDER BY created_at DESC`,
    [deps.caller.account_id],
  );

  return {
    keys: rows.map((r) => ({
      key_id: r.key_id,
      prefix: r.prefix,
      label: r.label,
      scopes: r.scopes,
      tier: r.tier,
      rotation_state: r.rotation_state,
      created_at: r.created_at.toISOString(),
      last_used_at: r.last_used_at?.toISOString() ?? null,
      expires_at: r.expires_at?.toISOString() ?? null,
    })),
  };
}
