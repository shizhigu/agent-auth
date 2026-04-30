/**
 * POST /api/agent-auth/recover-account-status — poll a recovery session.
 * SPEC §10.1 (variant of /registration-status accepting only pkr_ tokens).
 *
 * Cross-kind tokens (pak_/pad_/pav_) are rejected with 410 invalid_kind
 * by the underlying registrationStatus handler.
 */

import {
  registrationStatus,
  type RegistrationStatusResponse,
} from './registration-status.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export type RecoverAccountStatusResponse = RegistrationStatusResponse;

export interface RecoverAccountStatusDeps {
  readonly postgres: PostgresAdapter;
  /** Override 'now' for tests. Defaults to Date.now. */
  readonly now?: () => number;
}

export async function recoverAccountStatus(
  rawBody: unknown,
  deps: RecoverAccountStatusDeps,
): Promise<RegistrationStatusResponse> {
  return registrationStatus(rawBody, {
    postgres: deps.postgres,
    endpoint: 'recover',
    ...(deps.now !== undefined ? { now: deps.now } : {}),
  });
}
