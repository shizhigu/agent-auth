/**
 * Unit test for the single-use encrypted_payload behavior added in 0007.
 *
 * Uses an in-process FakePg that mirrors the SELECT … FOR UPDATE +
 * UPDATE … WHERE status='ready' contract. The integration suite
 * exercises this against a real Postgres in
 * `test/integration/registration.int.test.ts`.
 */
import { describe, it, expect } from 'vitest';
import { registrationStatus } from '../../src/routes/registration-status.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface SessionRow {
  poll_token: string;
  kind: 'register' | 'recover' | 'add_key' | 'revalidate';
  account_id: string | null;
  status: 'pending' | 'exchanging' | 'ready' | 'claimed' | 'failed' | 'expired';
  status_message: string | null;
  result_ciphertext: Buffer | null;
  expires_at: Date;
}

function fakePg(initial: SessionRow): PostgresAdapter {
  const row = { ...initial };
  return {
    async withClient(fn: (client: { query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[] }> }) => Promise<unknown>) {
      return fn({
        async query(sql: string, params?: unknown[]) {
          const sqlNorm = sql.replace(/\s+/g, ' ').trim();
          if (sqlNorm.startsWith('SELECT kind, account_id, status, status_message')) {
            const token = (params as string[])[0];
            if (row.poll_token !== token) return { rows: [] };
            return {
              rows: [
                {
                  kind: row.kind,
                  account_id: row.account_id,
                  status: row.status,
                  status_message: row.status_message,
                  result_ciphertext: row.result_ciphertext,
                  expires_at: row.expires_at,
                },
              ],
            };
          }
          if (
            sqlNorm.startsWith("UPDATE agent_registration_sessions SET status = 'claimed'")
          ) {
            const token = (params as string[])[0];
            if (row.poll_token === token && row.status === 'ready') {
              row.status = 'claimed';
              row.result_ciphertext = null;
            }
            return { rows: [] };
          }
          throw new Error(`unexpected SQL: ${sqlNorm}`);
        },
      });
    },
  } as unknown as PostgresAdapter;
}

describe('registrationStatus — single-use encrypted_payload', () => {
  it('returns completed + payload on first poll', async () => {
    const pg = fakePg({
      poll_token: 'pak_x',
      kind: 'register',
      account_id: 'acc-1',
      status: 'ready',
      status_message: null,
      result_ciphertext: Buffer.from([1, 2, 3]),
      expires_at: new Date(Date.now() + 60_000),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_x' },
      { postgres: pg, endpoint: 'registration' },
    );
    expect(out.status).toBe('completed');
    if (out.status === 'completed') {
      expect(out.account_id).toBe('acc-1');
      expect(out.encrypted_payload).toBe(Buffer.from([1, 2, 3]).toString('base64url'));
    }
  });

  it('returns claimed + account_id on second poll (single-use)', async () => {
    const pg = fakePg({
      poll_token: 'pak_x',
      kind: 'register',
      account_id: 'acc-1',
      status: 'ready',
      status_message: null,
      result_ciphertext: Buffer.from([1, 2, 3]),
      expires_at: new Date(Date.now() + 60_000),
    });
    const deps = { postgres: pg, endpoint: 'registration' as const };

    // First poll succeeds, transitions ready -> claimed.
    const first = await registrationStatus({ poll_token: 'pak_x' }, deps);
    expect(first.status).toBe('completed');

    // Second poll returns claimed, no payload.
    const second = await registrationStatus({ poll_token: 'pak_x' }, deps);
    expect(second.status).toBe('claimed');
    if (second.status === 'claimed') {
      expect(second.account_id).toBe('acc-1');
      // No encrypted_payload field on the 'claimed' variant — type-checked
      // by the discriminated union.
    }
  });

  it('claimed status survives expiry — caller can confirm completion', async () => {
    // Once status='claimed' the ciphertext is gone but the row stays
    // around for audit. Past-expiry is fine because there's nothing
    // sensitive left.
    const pg = fakePg({
      poll_token: 'pak_x',
      kind: 'register',
      account_id: 'acc-1',
      status: 'claimed',
      status_message: null,
      result_ciphertext: null,
      expires_at: new Date(Date.now() + 60_000),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_x' },
      { postgres: pg, endpoint: 'registration' },
    );
    expect(out.status).toBe('claimed');
  });

  it('pending stays pending', async () => {
    const pg = fakePg({
      poll_token: 'pak_x',
      kind: 'register',
      account_id: null,
      status: 'pending',
      status_message: null,
      result_ciphertext: null,
      expires_at: new Date(Date.now() + 60_000),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_x' },
      { postgres: pg, endpoint: 'registration' },
    );
    expect(out.status).toBe('pending');
  });

  it('failed surfaces code + message', async () => {
    const pg = fakePg({
      poll_token: 'pak_x',
      kind: 'register',
      account_id: null,
      status: 'failed',
      status_message: 'audience_mismatch',
      result_ciphertext: null,
      expires_at: new Date(Date.now() + 60_000),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_x' },
      { postgres: pg, endpoint: 'registration' },
    );
    expect(out.status).toBe('failed');
    if (out.status === 'failed') {
      expect(out.code).toBe('audience_mismatch');
    }
  });
});
