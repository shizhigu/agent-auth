import { describe, it, expect } from 'vitest';
import { recoverAccount } from '../../src/routes/recover-account.js';
import { recoverAccountStatus } from '../../src/routes/recover-account-status.js';
import type { AttestationContext, IdentityProvider } from '../../src/types.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

class StubProvider implements IdentityProvider {
  readonly name = 'github_app';
  async beginRegistration(_ctx: AttestationContext) {
    return { challenge_url: 'https://github.com/login/oauth/authorize?state=x' };
  }
  async exchangeOrVerify(): Promise<never> {
    throw new Error('not used');
  }
  async revalidate() {
    return { still_valid: true };
  }
}

interface FakeSession {
  poll_token: string;
  status: string;
  kind: string;
  expires_at: Date;
  account_id: string | null;
  result_ciphertext: Buffer | null;
  status_message: string | null;
}

class FakePg {
  sessions = new Map<string, FakeSession>();
  accounts = new Map<string, { status: string }>();

  async query(text: string, params: ReadonlyArray<unknown> = []) {
    if (/INSERT INTO agent_registration_sessions/.test(text)) {
      const poll_token = params[0] as string;
      const expires_at = params[10] as Date;
      this.sessions.set(poll_token, {
        poll_token,
        status: 'pending',
        kind: params[7] as string,
        expires_at,
        account_id: null,
        result_ciphertext: null,
        status_message: null,
      });
    }
    if (/INSERT INTO agent_recovery_approvals/.test(text)) {
      // accept blindly for test
    }
    return { rows: [], rowCount: 1 };
  }

  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    if (/SELECT status FROM agent_accounts/.test(text)) {
      const acc = this.accounts.get(params[0] as string);
      return ((acc ? { status: acc.status } : null) as unknown) as R | null;
    }
    if (/SELECT \* FROM agent_registration_sessions/.test(text)) {
      const row = this.sessions.get(params[0] as string);
      return ((row ?? null) as unknown) as R | null;
    }
    return null;
  }

  // recoverAccountStatus delegates to registrationStatus, which uses
  // withClient + SELECT FOR UPDATE for the ready -> claimed transition.
  async withClient<R>(
    fn: (client: { query: (sql: string, params?: ReadonlyArray<unknown>) => Promise<{ rows: unknown[] }> }) => Promise<R>,
  ): Promise<R> {
    const sessions = this.sessions;
    return fn({
      async query(sql: string, params: ReadonlyArray<unknown> = []) {
        const norm = sql.replace(/\s+/g, ' ').trim();
        if (norm.startsWith('SELECT kind, account_id, status, status_message')) {
          const row = sessions.get(params[0] as string);
          if (!row) return { rows: [] };
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
        if (norm.startsWith("UPDATE agent_registration_sessions SET status = 'claimed'")) {
          const row = sessions.get(params[0] as string);
          if (row && row.status === 'ready') {
            row.status = 'claimed';
            row.result_ciphertext = null;
          }
          return { rows: [] };
        }
        return { rows: [] };
      },
    });
  }
}

function makeDeps(pg: FakePg) {
  return {
    postgres: pg as unknown as PostgresAdapter,
    identity_providers: [new StubProvider()],
    redirect_uri: () => 'https://saas/callback',
    audience: () => 'Iv1.x',
    request_context: { ip_hash: Buffer.alloc(32), user_agent: 'agent' },
  };
}

describe('recoverAccount (SPEC §2.9)', () => {
  it('happy path: pkr_ poll_token + session row created with target_account_id', async () => {
    const pg = new FakePg();
    pg.accounts.set('00000000-0000-0000-0000-000000000001', { status: 'active' });
    const out = await recoverAccount(
      {
        provider: 'github_app',
        account_id: '00000000-0000-0000-0000-000000000001',
        client_pubkey: Buffer.alloc(32, 1).toString('base64url'),
      },
      makeDeps(pg),
    );
    expect(out.poll_token.startsWith('pkr_')).toBe(true);
    expect(out.challenge_url).toBeDefined();
    const session = pg.sessions.get(out.poll_token)!;
    expect(session.kind).toBe('recover');
  });

  it('rejects when account_id is missing', async () => {
    const pg = new FakePg();
    await expect(
      recoverAccount(
        {
          provider: 'github_app',
          client_pubkey: Buffer.alloc(32).toString('base64url'),
        },
        makeDeps(pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'missing_account_id_for_intent' });
  });

  it('rejects when account does not exist', async () => {
    const pg = new FakePg();
    await expect(
      recoverAccount(
        {
          provider: 'github_app',
          account_id: '00000000-0000-0000-0000-000000000099',
          client_pubkey: Buffer.alloc(32).toString('base64url'),
        },
        makeDeps(pg),
      ),
    ).rejects.toMatchObject({ status: 404, code: 'account_not_found' });
  });
});

describe('recoverAccountStatus (SPEC §10.1)', () => {
  it('rejects pak_ token at /recover-account-status (RT-21)', async () => {
    const pg = new FakePg();
    await expect(
      recoverAccountStatus(
        { poll_token: 'pak_' + 'x'.repeat(43) },
        { postgres: pg as unknown as PostgresAdapter },
      ),
    ).rejects.toMatchObject({ status: 410, code: 'invalid_kind' });
  });

  it('returns pending for an in-progress recovery session', async () => {
    const pg = new FakePg();
    const token = 'pkr_' + 'x'.repeat(43);
    pg.sessions.set(token, {
      poll_token: token,
      status: 'pending',
      kind: 'recover',
      expires_at: new Date(Date.now() + 60_000),
      account_id: null,
      result_ciphertext: null,
      status_message: null,
    });
    const out = await recoverAccountStatus(
      { poll_token: token },
      { postgres: pg as unknown as PostgresAdapter },
    );
    expect(out).toEqual({ status: 'pending' });
  });
});
