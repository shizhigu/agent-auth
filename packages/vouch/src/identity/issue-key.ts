/**
 * issueNewKey — shared key generation + persistence used by /callback
 * (first / additional key) and /rotate-key (M3 successor key).
 *
 * SPEC §2.2.2 step h. The flow:
 *   - public_id  = base64url(randombytes(6))   (8 chars, ~48 bits)
 *   - secret     = randombytes(32)             (256 bits)
 *   - key_id     = 'agk_' + public_id
 *   - prefix     = base64url(secret)[:8]       (display only, never the key)
 *   - kms_pepper = await kms.getCurrentPepper()
 *   - key_hash   = HMAC-SHA256(kms_pepper, secret)
 *   - INSERT agent_api_keys (...)
 *
 * Returns enough material for the caller to seal a §2.6 payload:
 *   { key, key_id, account_id, scopes, tier, is_first_key, issued_at }
 *
 * Wire form of the bearer token (consumed by validate-key) is
 *   <key_id>.<base64url(secret)>
 * That format is also what the SDK should put in `payload.key`.
 */

import { randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import type { KmsAdapter } from '../storage/kms-adapter.js';
import { hmacWithPepper } from '../crypto/hmac-pepper.js';
import type { Tier } from '../types.js';

export interface IssueNewKeyInput {
  /** owning account */
  readonly account_id: string;
  /** identity that authorized this issuance (FK target) */
  readonly issuing_identity_id: string;
  /** account.tier at issuance time (denormalized for §3.5 rotation_state cache layout) */
  readonly tier: Tier;
  /** v0.1 default scopes per §2.2.2 step h ("read", "self:rotate") */
  readonly scopes: ReadonlyArray<string>;
  /** Optional human-friendly label (≤64 chars) supplied at /begin-registration */
  readonly label?: string;
  /** Predecessor key id (when called from rotate-key); null on registration */
  readonly created_by_key_id?: string;
  /** Optional explicit expires_at; default null = no expiry */
  readonly expires_at?: Date;
}

export interface IssueNewKeyResult {
  /** UUID of the inserted agent_api_keys row. */
  readonly id: string;
  readonly key_id: string;
  /** Wire-form bearer token: `${key_id}.${base64url(secret)}`. */
  readonly bearer: string;
  /** Raw 32-byte secret. Caller should not log this. */
  readonly secret: Buffer;
  /** Display prefix (first 8 chars of base64url(secret)) — safe to surface. */
  readonly prefix: string;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: Tier;
  readonly created_at: Date;
  readonly key_pepper_version: number;
}

export interface SealedPayloadInput {
  readonly key_bearer: string;
  readonly key_id: string;
  readonly account_id: string;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: Tier;
  readonly is_first_key: boolean;
  readonly issued_at: Date;
}

export function buildSealedPayload(input: SealedPayloadInput): Buffer {
  // Schema is fixed by SPEC §2.6. Field order matches the spec block so a
  // hash-sniff test (e.g. canonical comparison) stays predictable. Note: the
  // payload travels inside a sealed-box; recipients accept any field order
  // since they JSON.parse the cleartext.
  const obj = {
    key: input.key_bearer,
    key_id: input.key_id,
    account_id: input.account_id,
    scopes: [...input.scopes],
    tier: input.tier,
    is_first_key: input.is_first_key,
    issued_at: input.issued_at.toISOString(),
  };
  return Buffer.from(JSON.stringify(obj), 'utf8');
}

/**
 * INSERT a new agent_api_keys row in the supplied PoolClient (so the caller
 * can wrap it in the same transaction that creates the account/identity).
 */
export async function issueNewKey(
  client: PoolClient,
  kms: KmsAdapter,
  input: IssueNewKeyInput,
): Promise<IssueNewKeyResult> {
  const public_id = randomBytes(6).toString('base64url'); // 8 chars
  const secret = randomBytes(32);
  const secret_b64 = secret.toString('base64url');
  const key_id = `agk_${public_id}`;
  const prefix = secret_b64.slice(0, 8);
  const pepper = await kms.getCurrentPepper();
  const key_hash = hmacWithPepper(pepper.data, secret);

  const insert = await client.query<{
    id: string;
    created_at: Date;
  }>(
    `INSERT INTO agent_api_keys (
       account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
       prefix, label, scopes, tier, version, rotation_state,
       created_by_key_id, expires_at
     )
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, 1, 'active', $10, $11)
     RETURNING id, created_at`,
    [
      input.account_id,
      input.issuing_identity_id,
      key_id,
      key_hash,
      pepper.version,
      prefix,
      input.label ?? null,
      [...input.scopes],
      input.tier,
      input.created_by_key_id ?? null,
      input.expires_at ?? null,
    ],
  );

  const row = insert.rows[0];
  if (!row) throw new Error('issue_new_key_insert_returned_no_row');

  return {
    id: row.id,
    key_id,
    bearer: `${key_id}.${secret_b64}`,
    secret,
    prefix,
    scopes: input.scopes,
    tier: input.tier,
    created_at: row.created_at,
    key_pepper_version: pepper.version,
  };
}
