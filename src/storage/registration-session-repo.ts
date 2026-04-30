/**
 * Registration session repository — wraps the agent_registration_sessions
 * table (SPEC §3.6). All session lifecycle moves go through this module
 * so the route handlers stay framework-agnostic.
 */

import type { PostgresAdapter } from './postgres-adapter.js';
import type {
  SessionKind,
  SessionStatus,
} from '../types.js';

export interface RegistrationSessionRow {
  readonly poll_token: string;
  readonly nonce: string;
  readonly pkce_verifier: string;
  readonly pkce_challenge: string;
  readonly audience: string;
  readonly expected_provider: string;
  readonly redirect_uri: string;
  readonly kind: SessionKind;
  readonly target_account_id: string | null;
  readonly client_pubkey: Buffer;
  readonly status: SessionStatus;
  readonly status_message: string | null;
  readonly result_ciphertext: Buffer | null;
  readonly account_id: string | null;
  readonly expires_at: Date;
  readonly created_at: Date;
}

export interface InsertSessionInput {
  readonly poll_token: string;
  readonly nonce: string;
  readonly pkce_verifier: string;
  readonly pkce_challenge: string;
  readonly audience: string;
  readonly expected_provider: string;
  readonly redirect_uri: string;
  readonly kind: SessionKind;
  readonly target_account_id?: string;
  readonly client_pubkey: Buffer;
  readonly expires_at: Date;
}

export class RegistrationSessionRepo {
  constructor(private readonly pg: PostgresAdapter) {}

  async insert(input: InsertSessionInput): Promise<void> {
    await this.pg.query(
      `INSERT INTO agent_registration_sessions (
         poll_token, nonce, pkce_verifier, pkce_challenge,
         audience, expected_provider, redirect_uri, kind,
         target_account_id, client_pubkey, status, expires_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11)`,
      [
        input.poll_token,
        input.nonce,
        input.pkce_verifier,
        input.pkce_challenge,
        input.audience,
        input.expected_provider,
        input.redirect_uri,
        input.kind,
        input.target_account_id ?? null,
        input.client_pubkey,
        input.expires_at,
      ],
    );
  }

  async getByPollToken(poll_token: string): Promise<RegistrationSessionRow | null> {
    return this.pg.queryOne<RegistrationSessionRow>(
      `SELECT * FROM agent_registration_sessions WHERE poll_token = $1`,
      [poll_token],
    );
  }

  async getByNonceForUpdate(nonce: string): Promise<RegistrationSessionRow | null> {
    return this.pg.queryOne<RegistrationSessionRow>(
      `SELECT * FROM agent_registration_sessions
        WHERE nonce = $1 AND status = 'pending' AND expires_at > now()
        FOR UPDATE`,
      [nonce],
    );
  }

  async transitionStatus(
    poll_token: string,
    from: SessionStatus,
    to: SessionStatus,
    extras?: {
      status_message?: string;
      result_ciphertext?: Buffer;
      account_id?: string;
    },
  ): Promise<boolean> {
    const sets: string[] = ['status = $3'];
    const params: unknown[] = [poll_token, from, to];
    let pi = 4;
    if (extras?.status_message !== undefined) {
      sets.push(`status_message = $${pi++}`);
      params.push(extras.status_message);
    }
    if (extras?.result_ciphertext !== undefined) {
      sets.push(`result_ciphertext = $${pi++}`);
      params.push(extras.result_ciphertext);
    }
    if (extras?.account_id !== undefined) {
      sets.push(`account_id = $${pi++}`);
      params.push(extras.account_id);
    }
    const { rowCount } = await this.pg.query(
      `UPDATE agent_registration_sessions
          SET ${sets.join(', ')}
        WHERE poll_token = $1 AND status = $2`,
      params,
    );
    return rowCount > 0;
  }

  /** Reaper: §3.6 — drop sessions one hour past expires_at. */
  async deleteExpired(now: Date = new Date()): Promise<number> {
    const cutoff = new Date(now.getTime() - 60 * 60 * 1000);
    const { rowCount } = await this.pg.query(
      `DELETE FROM agent_registration_sessions WHERE expires_at < $1`,
      [cutoff],
    );
    return rowCount;
  }
}
