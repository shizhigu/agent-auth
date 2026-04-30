/**
 * Admin CLI dispatcher. SPEC §8.1.
 *
 * Framework-agnostic: the actual `agent-auth admin <command>` binary just
 * parses argv into the AdminCommand shape and calls `runAdminCommand`.
 * Tests and other harnesses can call it directly.
 *
 * Every destructive command goes through:
 *   1. JIT RBAC check — admin must hold an unexpired grant for
 *      'agent_auth_admin'.
 *   2. WebAuthn verify — admin presents a hardware-key assertion.
 *   3. Two-person check (if required by op) — co-signer signature.
 *   4. Audit row written (kind = 'admin_<op>') BEFORE side-effects.
 *   5. Side-effect: dispatch to the runbook implementation (RB-1..RB-9).
 *
 * Read-only commands (list-*, show-*, audit-tail) skip steps 2-3 but
 * still require a JIT grant + audit row.
 */

import { AgentAuthError } from '../errors.js';
import { writeAuditRow, type AuditDbDeps } from '../audit/db-writer.js';
import {
  assertWebAuthn,
  type WebAuthnAssertion,
  type WebAuthnVerifier,
} from './webauthn.js';
import {
  verifyCoSignature,
  type CoSignerEnvelope,
} from './two-person.js';
import { JitRbac } from './jit-rbac.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export type AdminCommandName =
  | 'list-accounts'
  | 'show-account'
  | 'list-keys'
  | 'show-key'
  | 'audit-tail'
  | 'revoke-key' // RB-1
  | 'suspend-account' // RB-2
  | 'resolve-idempotency' // RB-3
  | 'flush-cache' // RB-4 (two-person)
  | 'unblock-identity' // RB-5
  | 'reconcile-redis-sets' // RB-7
  | 'webhook-backfill' // RB-9
  | 'close-account' // two-person
  | 'force-revoke-all' // two-person
  | 'reset-barrier'; // two-person

export const TWO_PERSON_REQUIRED: ReadonlySet<AdminCommandName> = new Set([
  'flush-cache',
  'close-account',
  'force-revoke-all',
  'reset-barrier',
]);

export const READ_ONLY_COMMANDS: ReadonlySet<AdminCommandName> = new Set([
  'list-accounts',
  'show-account',
  'list-keys',
  'show-key',
  'audit-tail',
]);

export interface AdminCommandInput {
  readonly command: AdminCommandName;
  readonly admin_id: string;
  /** JIT grant the admin holds — issued via `agent-auth admin grant`. */
  readonly jit_grant_id: string;
  readonly reason: string;
  /** WebAuthn assertion. Required for non-read-only commands. */
  readonly webauthn_assertion?: WebAuthnAssertion;
  /** Co-signer envelope + sig, required for TWO_PERSON_REQUIRED. */
  readonly co_signer?: {
    readonly envelope: CoSignerEnvelope;
    readonly signature_hex: string;
  };
  /** Command-specific options. Validated by each handler. */
  readonly options: Record<string, unknown>;
}

export interface AdminCommandHandler {
  run(
    input: AdminCommandInput,
    deps: AdminDispatchDeps,
  ): Promise<unknown>;
}

export interface AdminDispatchDeps {
  readonly postgres: PostgresAdapter;
  readonly jit_rbac: JitRbac;
  readonly webauthn: WebAuthnVerifier;
  readonly internal_secret: Buffer;
  readonly audit: AuditDbDeps;
  /** Map of command → handler. Tests can override. */
  readonly handlers: Readonly<Partial<Record<AdminCommandName, AdminCommandHandler>>>;
  readonly now?: () => number;
}

export async function runAdminCommand(
  input: AdminCommandInput,
  deps: AdminDispatchDeps,
): Promise<unknown> {
  // 1. JIT grant check.
  deps.jit_rbac.assertGrant(input.jit_grant_id, 'agent_auth_admin');

  // 2. WebAuthn for non-read-only.
  if (!READ_ONLY_COMMANDS.has(input.command)) {
    if (!input.webauthn_assertion) {
      throw new AgentAuthError(401, 'invalid_request', 'webauthn_required');
    }
    await assertWebAuthn(deps.webauthn, {
      admin_id: input.admin_id,
      operation: input.command,
      assertion: input.webauthn_assertion,
    });
  }

  // 3. Two-person rule.
  if (TWO_PERSON_REQUIRED.has(input.command)) {
    if (!input.co_signer) {
      throw new AgentAuthError(401, 'invalid_request', 'co_signer_required');
    }
    if (input.co_signer.envelope.op !== input.command) {
      throw new AgentAuthError(401, 'invalid_request', 'co_signer_op_mismatch');
    }
    verifyCoSignature(
      input.co_signer.envelope,
      input.co_signer.signature_hex,
      deps.internal_secret,
      deps.now ? { now_ms: deps.now() } : {},
    );
  }

  // 4. Audit BEFORE side-effects.
  await writeAuditRow(
    {
      event_type: `admin_${input.command}`,
      endpoint: 'cli',
      status_class: 2,
      meta: {
        admin_id: input.admin_id,
        reason: input.reason,
        options: input.options,
        ...(input.co_signer
          ? {
              co_signer_initiator: input.co_signer.envelope.initiator,
              co_signer_nonce: input.co_signer.envelope.nonce,
            }
          : {}),
      },
    },
    deps.audit,
  );

  // 5. Dispatch.
  const handler = deps.handlers[input.command];
  if (!handler) {
    throw new AgentAuthError(400, 'invalid_request', `unknown_command: ${input.command}`);
  }
  return handler.run(input, deps);
}
