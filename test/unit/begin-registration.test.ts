import { describe, it, expect, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { beginRegistration } from '../../src/routes/begin-registration.js';
import { registrationStatus } from '../../src/routes/registration-status.js';
import { reapRegistrationSessions } from '../../src/jobs/reaper.js';
import type {
  AttestationContext,
  Attestation,
  IdentityProvider,
} from '../../src/types.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

// ---------------------------------------------------------------------------
// Tiny fake PG that understands the queries the routes issue.
// ---------------------------------------------------------------------------

interface FakeSessionRow {
  poll_token: string;
  nonce: string;
  pkce_verifier: string;
  pkce_challenge: string;
  audience: string;
  expected_provider: string;
  redirect_uri: string;
  kind: string;
  target_account_id: string | null;
  client_pubkey: Buffer;
  status: string;
  status_message: string | null;
  result_ciphertext: Buffer | null;
  account_id: string | null;
  expires_at: Date;
  created_at: Date;
}

class FakePg {
  sessions = new Map<string, FakeSessionRow>();
  accounts = new Map<string, { status: string }>();

  async query(text: string, params: ReadonlyArray<unknown> = []) {
    if (text.startsWith('INSERT INTO agent_registration_sessions')) {
      const row: FakeSessionRow = {
        poll_token: params[0] as string,
        nonce: params[1] as string,
        pkce_verifier: params[2] as string,
        pkce_challenge: params[3] as string,
        audience: params[4] as string,
        expected_provider: params[5] as string,
        redirect_uri: params[6] as string,
        kind: params[7] as string,
        target_account_id: (params[8] as string | null) ?? null,
        client_pubkey: params[9] as Buffer,
        status: 'pending',
        status_message: null,
        result_ciphertext: null,
        account_id: null,
        expires_at: params[10] as Date,
        created_at: new Date(),
      };
      this.sessions.set(row.poll_token, row);
      return { rows: [], rowCount: 1 };
    }
    if (text.startsWith('UPDATE agent_registration_sessions')) {
      // Strict mode: parse the SET clause params to figure out what to update.
      // The route's transitionStatus is the only updater; format is fixed.
      const poll_token = params[0] as string;
      const from = params[1] as string;
      const to = params[2] as string;
      const row = this.sessions.get(poll_token);
      if (!row || row.status !== from) return { rows: [], rowCount: 0 };
      row.status = to;
      // Trailing positional args after [pt, from, to] are the optional
      // status_message, result_ciphertext, account_id (in the order in
      // which transitionStatus appended them).
      let i = 3;
      if (text.includes('status_message')) row.status_message = params[i++] as string;
      if (text.includes('result_ciphertext'))
        row.result_ciphertext = params[i++] as Buffer;
      if (text.includes('account_id')) row.account_id = params[i++] as string;
      return { rows: [], rowCount: 1 };
    }
    if (text.startsWith('DELETE FROM agent_registration_sessions')) {
      const cutoff = params[0] as Date;
      let n = 0;
      for (const [k, v] of this.sessions) {
        if (v.expires_at.getTime() < cutoff.getTime()) {
          this.sessions.delete(k);
          n++;
        }
      }
      return { rows: [], rowCount: n };
    }
    return { rows: [], rowCount: 0 };
  }

  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    if (text.startsWith('SELECT status FROM agent_accounts')) {
      const acc = this.accounts.get(params[0] as string);
      return ((acc ? { status: acc.status } : null) as unknown) as R | null;
    }
    if (text.startsWith('SELECT * FROM agent_registration_sessions')) {
      // SELECT BY poll_token = $1
      const row = this.sessions.get(params[0] as string);
      return ((row ?? null) as unknown) as R | null;
    }
    return null;
  }
}

class StubProvider implements IdentityProvider {
  readonly name: string;
  beginCalled: AttestationContext | null = null;

  constructor(name = 'github_app') {
    this.name = name;
  }

  async beginRegistration(ctx: AttestationContext) {
    this.beginCalled = ctx;
    return {
      challenge_url: `https://github.com/login/oauth/authorize?state=${ctx.nonce}&code_challenge=${ctx.pkce_challenge}`,
    };
  }

  async exchangeOrVerify(): Promise<Attestation> {
    throw new Error('not used in this test');
  }

  async revalidate() {
    return { still_valid: true };
  }
}

class FailingProvider extends StubProvider {
  override async beginRegistration(): Promise<never> {
    throw new Error('upstream unavailable');
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clientPubkeyB64(): string {
  return randomBytes(32).toString('base64url');
}

function makeDeps(provider: IdentityProvider, pg: FakePg) {
  return {
    postgres: pg as unknown as PostgresAdapter,
    identity_providers: [provider],
    redirect_uri: () => 'https://saas.example/api/agent-auth/callback/github_app',
    audience: () => 'Iv1.abcdef',
    request_context: { ip_hash: Buffer.alloc(32, 1), user_agent: 'agent-sdk/1.0' },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('beginRegistration (SPEC §10.1, §2.2.2)', () => {
  let pg: FakePg;
  let provider: StubProvider;

  beforeEach(() => {
    pg = new FakePg();
    provider = new StubProvider();
  });

  it('happy path: returns a pak_ poll_token + challenge_url and persists session', async () => {
    const out = await beginRegistration(
      {
        provider: 'github_app',
        intent: 'register',
        client_pubkey: clientPubkeyB64(),
      },
      makeDeps(provider, pg),
    );
    expect(out.poll_token.startsWith('pak_')).toBe(true);
    expect(out.challenge_url).toContain('github.com/login/oauth/authorize');
    expect(out.poll_interval_seconds).toBe(2);
    expect(out.expires_at).toMatch(/\d{4}-\d{2}-\d{2}T/);

    const row = pg.sessions.get(out.poll_token)!;
    expect(row.status).toBe('pending');
    expect(row.kind).toBe('register');
    expect(row.audience).toBe('Iv1.abcdef');
    expect(row.client_pubkey.length).toBe(32);
    expect(provider.beginCalled?.intent).toBe('register');
    expect(provider.beginCalled?.poll_token).toBe(out.poll_token);
    expect(provider.beginCalled?.pkce_challenge_method).toBe('S256');
  });

  it('intent=recover requires account_id and account exists', async () => {
    await expect(
      beginRegistration(
        { provider: 'github_app', intent: 'recover', client_pubkey: clientPubkeyB64() },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'missing_account_id_for_intent' });

    await expect(
      beginRegistration(
        {
          provider: 'github_app',
          intent: 'recover',
          client_pubkey: clientPubkeyB64(),
          account_id: '00000000-0000-0000-0000-000000000001',
        },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 404, code: 'account_not_found' });
  });

  it('returns 410 account_closed for closed accounts', async () => {
    pg.accounts.set('00000000-0000-0000-0000-000000000001', { status: 'closed' });
    await expect(
      beginRegistration(
        {
          provider: 'github_app',
          intent: 'recover',
          client_pubkey: clientPubkeyB64(),
          account_id: '00000000-0000-0000-0000-000000000001',
        },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 410, code: 'account_closed' });
  });

  it('returns 403 account_suspended_unsuspend_first for suspended accounts', async () => {
    pg.accounts.set('00000000-0000-0000-0000-000000000001', { status: 'suspended' });
    await expect(
      beginRegistration(
        {
          provider: 'github_app',
          intent: 'recover',
          client_pubkey: clientPubkeyB64(),
          account_id: '00000000-0000-0000-0000-000000000001',
        },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 403, code: 'account_suspended_unsuspend_first' });
  });

  it('rejects unknown providers', async () => {
    await expect(
      beginRegistration(
        { provider: 'unknown', intent: 'register', client_pubkey: clientPubkeyB64() },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_provider' });
  });

  it('rejects invalid_intent', async () => {
    await expect(
      beginRegistration(
        { provider: 'github_app', intent: 'bogus', client_pubkey: clientPubkeyB64() },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_intent' });
  });

  it('rejects invalid_label > 64 chars', async () => {
    await expect(
      beginRegistration(
        {
          provider: 'github_app',
          intent: 'register',
          client_pubkey: clientPubkeyB64(),
          label: 'x'.repeat(65),
        },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_label' });
  });

  it('rejects invalid_client_pubkey on wrong size', async () => {
    await expect(
      beginRegistration(
        {
          provider: 'github_app',
          intent: 'register',
          client_pubkey: Buffer.alloc(20).toString('base64url'),
        },
        makeDeps(provider, pg),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_client_pubkey' });
  });

  it('surfaces 503 idp_circuit_open when provider throws', async () => {
    const failing = new FailingProvider();
    await expect(
      beginRegistration(
        { provider: 'github_app', intent: 'register', client_pubkey: clientPubkeyB64() },
        makeDeps(failing, pg),
      ),
    ).rejects.toMatchObject({ status: 503, code: 'idp_circuit_open' });
  });
});

describe('registrationStatus (SPEC §10.1)', () => {
  it('returns pending while session is in progress', async () => {
    const pg = new FakePg();
    pg.sessions.set('pak_' + 'x'.repeat(43), {
      poll_token: 'pak_' + 'x'.repeat(43),
      nonce: 'n',
      pkce_verifier: 'v',
      pkce_challenge: 'c',
      audience: 'a',
      expected_provider: 'github_app',
      redirect_uri: 'r',
      kind: 'register',
      target_account_id: null,
      client_pubkey: Buffer.alloc(32),
      status: 'pending',
      status_message: null,
      result_ciphertext: null,
      account_id: null,
      expires_at: new Date(Date.now() + 60_000),
      created_at: new Date(),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_' + 'x'.repeat(43) },
      { postgres: pg as unknown as PostgresAdapter, endpoint: 'registration' },
    );
    expect(out).toEqual({ status: 'pending' });
  });

  it('returns completed with sealed-box ciphertext + account_id', async () => {
    const pg = new FakePg();
    const ct = Buffer.from('sealed');
    pg.sessions.set('pak_' + 'x'.repeat(43), {
      poll_token: 'pak_' + 'x'.repeat(43),
      nonce: 'n',
      pkce_verifier: 'v',
      pkce_challenge: 'c',
      audience: 'a',
      expected_provider: 'github_app',
      redirect_uri: 'r',
      kind: 'register',
      target_account_id: null,
      client_pubkey: Buffer.alloc(32),
      status: 'ready',
      status_message: null,
      result_ciphertext: ct,
      account_id: 'acc-1',
      expires_at: new Date(Date.now() + 60_000),
      created_at: new Date(),
    });
    const out = await registrationStatus(
      { poll_token: 'pak_' + 'x'.repeat(43) },
      { postgres: pg as unknown as PostgresAdapter, endpoint: 'registration' },
    );
    expect(out).toEqual({
      status: 'completed',
      account_id: 'acc-1',
      encrypted_payload: ct.toString('base64url'),
      is_first_key: true,
    });
  });

  it('rejects pkr_ token at /registration-status (RT-21 session-fixation)', async () => {
    const pg = new FakePg();
    await expect(
      registrationStatus(
        { poll_token: 'pkr_' + 'x'.repeat(43) },
        { postgres: pg as unknown as PostgresAdapter, endpoint: 'registration' },
      ),
    ).rejects.toMatchObject({ status: 410, code: 'invalid_kind' });
  });

  it('returns 410 session_expired for unknown poll_token', async () => {
    const pg = new FakePg();
    await expect(
      registrationStatus(
        { poll_token: 'pak_' + 'x'.repeat(43) },
        { postgres: pg as unknown as PostgresAdapter, endpoint: 'registration' },
      ),
    ).rejects.toMatchObject({ status: 410, code: 'session_expired' });
  });
});

describe('reapRegistrationSessions (SPEC §3.6)', () => {
  it('deletes sessions older than 1h past expires_at', async () => {
    const pg = new FakePg();
    const now = new Date('2026-04-30T12:00:00Z');
    pg.sessions.set('old', {
      poll_token: 'old',
      nonce: 'n',
      pkce_verifier: 'v',
      pkce_challenge: 'c',
      audience: 'a',
      expected_provider: 'github_app',
      redirect_uri: 'r',
      kind: 'register',
      target_account_id: null,
      client_pubkey: Buffer.alloc(32),
      status: 'expired',
      status_message: null,
      result_ciphertext: null,
      account_id: null,
      expires_at: new Date(now.getTime() - 2 * 60 * 60 * 1000), // 2h old
      created_at: new Date(),
    });
    pg.sessions.set('fresh', {
      poll_token: 'fresh',
      nonce: 'n2',
      pkce_verifier: 'v',
      pkce_challenge: 'c',
      audience: 'a',
      expected_provider: 'github_app',
      redirect_uri: 'r',
      kind: 'register',
      target_account_id: null,
      client_pubkey: Buffer.alloc(32),
      status: 'pending',
      status_message: null,
      result_ciphertext: null,
      account_id: null,
      expires_at: new Date(now.getTime() + 60_000),
      created_at: new Date(),
    });
    const result = await reapRegistrationSessions(pg as unknown as PostgresAdapter, now);
    expect(result.registration_sessions_deleted).toBe(1);
    expect(pg.sessions.has('old')).toBe(false);
    expect(pg.sessions.has('fresh')).toBe(true);
  });
});
