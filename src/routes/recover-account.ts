/**
 * POST /api/agent-auth/recover-account — initiate recovery. SPEC §2.9, §10.1.
 *
 * Same body as /begin-registration except `intent` is hard-coded to 'recover'
 * and `account_id` is required. The handler:
 *   1. Forces `intent='recover'` (defensive — even if caller sends something else).
 *   2. Calls beginRegistration to mint pkr_<token>, run the IdP authorize step,
 *      and persist the session row (target_account_id bound — RT-31).
 *   3. If `recover_account.approval_webhook_url` is configured, fires the
 *      signed owner-approval webhook before returning. The agent SDK keeps
 *      polling /recover-account-status until the owner approves AND the
 *      OAuth callback completes.
 *
 * The recovery flow itself (case C re-activation, identity-account match)
 * is implemented in /callback (§2.2.2 step g case C / RT-31 guard).
 */

import { z } from 'zod';
import { AgentAuthError } from '../errors.js';
import {
  beginRegistration,
  type BeginRegistrationDeps,
  type BeginRegistrationResponse,
} from './begin-registration.js';
import {
  emitOwnerApprovalRequest,
  type OwnerApprovalConfig,
} from '../identity/owner-approval-sign.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

const RecoverAccountBody = z
  .object({
    provider: z.string().min(1),
    account_id: z.string().uuid(),
    label: z.string().max(64).optional(),
    use_device_flow: z.boolean().optional(),
    client_pubkey: z.string(),
  })
  .strict();

export interface RecoverAccountDeps extends BeginRegistrationDeps {
  readonly owner_approval?: OwnerApprovalConfig;
}

export interface RecoverAccountResponse extends BeginRegistrationResponse {
  /** Present when owner approval is required and the webhook was sent. */
  readonly approval_required?: boolean;
}

export async function recoverAccount(
  rawBody: unknown,
  deps: RecoverAccountDeps,
): Promise<RecoverAccountResponse> {
  const parsed = RecoverAccountBody.safeParse(rawBody);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    if (issue?.path.includes('account_id')) {
      throw new AgentAuthError(400, 'missing_account_id_for_intent');
    }
    if (issue?.path.includes('client_pubkey')) {
      throw new AgentAuthError(400, 'invalid_client_pubkey');
    }
    if (issue?.path.includes('provider')) {
      throw new AgentAuthError(400, 'invalid_provider');
    }
    if (issue?.path.includes('label')) {
      throw new AgentAuthError(400, 'invalid_label');
    }
    throw new AgentAuthError(400, 'invalid_request');
  }

  const out = await beginRegistration(
    {
      provider: parsed.data.provider,
      intent: 'recover',
      account_id: parsed.data.account_id,
      ...(parsed.data.label !== undefined ? { label: parsed.data.label } : {}),
      ...(parsed.data.use_device_flow !== undefined
        ? { use_device_flow: parsed.data.use_device_flow }
        : {}),
      client_pubkey: parsed.data.client_pubkey,
    },
    deps,
  );

  if (deps.owner_approval) {
    await emitOwnerApprovalRequest(
      deps.postgres,
      deps.owner_approval,
      {
        account_id: parsed.data.account_id,
        poll_token: out.poll_token,
      },
    );
    return { ...out, approval_required: true };
  }
  return out;
}

export { type PostgresAdapter };
