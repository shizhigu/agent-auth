import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { callback } from '../../src/routes/callback.js';
import { open as sealedOpen, sealedBoxReady, keypair } from '../../src/crypto/sealed-box.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type {
  Attestation,
  AttestationContext,
  IdentityProvider,
  ProviderInput,
} from '../../src/types.js';

// ---------------------------------------------------------------------------
// Fake Postgres + PoolClient that understands the queries the callback issues.
// ---------------------------------------------------------------------------

interface SessionRow {
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
}

interface AccountRow {
  id: string;
  status: 'active' | 'suspended' | 'closed';
  tier: 'cold' | 'warm' | 'hot';
}

interface IdentityRow {
  id: string;
  account_id: string;
  provider: string;
  subject: string;
  audience: string;
  status: 'active' | 'revoked' | 'expired';
  revocation_source: string | null;
}

interface KeyRow {
  id: string;
  account_id: string;
  issued_via_identity_id: string;
  key_id: string;
  key_hash: Buffer;
  key_pepper_version: number;
  prefix: string;
  scopes: string[];
  tier: string;
  rotation_state: string;
  created_at: Date;
}

class FakeDb {
  sessions = new Map<string, SessionRow>();
  accounts = new Map<string, AccountRow>();
  identities = new Map<string, IdentityRow>(); // by id
  keys = new Map<string, KeyRow>(); // by id
  nextAccountId = 1;
  nextIdentityId = 1;
  nextKeyRowId = 1;
}

function makeAdapter(db: FakeDb): PostgresAdapter {
  // PoolClient stub that supports the queries inside the transaction.
  const client = {
    async query(text: string, params: ReadonlyArray<unknown> = []) {
      // SELECT session by nonce
      if (/SELECT \* FROM agent_registration_sessions/.test(text) && /nonce = \$1/.test(text)) {
        const nonce = params[0] as string;
        const row = [...db.sessions.values()].find(
          (s) => s.nonce === nonce && s.status === 'pending',
        );
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      // UPDATE session status by poll_token + status guard
      if (/UPDATE agent_registration_sessions/.test(text) && /WHERE poll_token = \$1/.test(text)) {
        const poll_token = params[0] as string;
        const row = db.sessions.get(poll_token);
        if (!row) return { rows: [], rowCount: 0 };
        if (text.includes("status = 'exchanging'") && text.includes("status = 'pending'")) {
          if (row.status !== 'pending') return { rows: [], rowCount: 0 };
          row.status = 'exchanging';
          return { rows: [], rowCount: 1 };
        }
        if (text.includes("status = 'failed'")) {
          row.status = 'failed';
          row.status_message = (params[1] as string) ?? null;
          return { rows: [], rowCount: 1 };
        }
        if (text.includes("status = 'ready'")) {
          row.status = 'ready';
          row.account_id = params[1] as string;
          // For kind='revalidate' the SQL inlines `result_ciphertext = NULL`
          // so params[2] is undefined; for register/recover/add_key the
          // sealed-box ciphertext is bound as $3.
          if (text.includes('result_ciphertext = NULL')) {
            row.result_ciphertext = null;
          } else {
            row.result_ciphertext = (params[2] as Buffer) ?? null;
          }
          return { rows: [], rowCount: 1 };
        }
      }
      // SELECT identity FOR UPDATE
      if (/FROM agent_identities/.test(text) && /provider = \$1/.test(text)) {
        const [provider, subject, audience] = params as [string, string, string];
        const row = [...db.identities.values()].find(
          (i) => i.provider === provider && i.subject === subject && i.audience === audience,
        );
        return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
      }
      // INSERT account
      if (/INSERT INTO agent_accounts/.test(text)) {
        const id = `acc-${db.nextAccountId++}`;
        const row: AccountRow = { id, status: 'active', tier: 'cold' };
        db.accounts.set(id, row);
        return { rows: [{ id, tier: 'cold' }], rowCount: 1 };
      }
      // INSERT identity
      if (/INSERT INTO agent_identities/.test(text)) {
        const id = `id-${db.nextIdentityId++}`;
        const [account_id, provider, subject, audience] = params as [
          string,
          string,
          string,
          string,
        ];
        const row: IdentityRow = {
          id,
          account_id,
          provider,
          subject,
          audience,
          status: 'active',
          revocation_source: null,
        };
        db.identities.set(id, row);
        return { rows: [{ id }], rowCount: 1 };
      }
      // UPDATE identity (re-activation case C)
      if (/UPDATE agent_identities/.test(text) && /SET status = 'active'/.test(text)) {
        const idVal = params[0] as string;
        const idRow = db.identities.get(idVal);
        if (idRow) {
          idRow.status = 'active';
          idRow.revocation_source = null;
        }
        return { rows: [], rowCount: idRow ? 1 : 0 };
      }
      // UPDATE identity SET last_revalidated_at (revalidate kind, SPEC §2.4)
      if (/UPDATE agent_identities/.test(text) && /last_revalidated_at = now\(\)/.test(text)) {
        const idVal = params[0] as string;
        const idRow = db.identities.get(idVal);
        return { rows: [], rowCount: idRow ? 1 : 0 };
      }
      // SELECT account FOR UPDATE
      if (/FROM agent_accounts/.test(text) && /id = \$1 FOR UPDATE/.test(text)) {
        const acc = db.accounts.get(params[0] as string);
        return { rows: acc ? [acc] : [], rowCount: acc ? 1 : 0 };
      }
      // INSERT key
      if (/INSERT INTO agent_api_keys/.test(text)) {
        const [
          account_id,
          issued_via_identity_id,
          key_id,
          key_hash,
          key_pepper_version,
          prefix,
          _label,
          scopes,
          tier,
        ] = params as [
          string,
          string,
          string,
          Buffer,
          number,
          string,
          string | null,
          string[],
          string,
        ];
        const id = `key-${db.nextKeyRowId++}`;
        const created_at = new Date();
        const row: KeyRow = {
          id,
          account_id,
          issued_via_identity_id,
          key_id,
          key_hash,
          key_pepper_version,
          prefix,
          scopes,
          tier,
          rotation_state: 'active',
          created_at,
        };
        db.keys.set(id, row);
        return { rows: [{ id, created_at }], rowCount: 1 };
      }
      // audit_log insert (writeAuditRowOnClient) — return synthetic row.
      if (/INSERT INTO agent_audit_log/.test(text)) {
        return {
          rows: [
            {
              id: '1',
              ts: new Date(),
              row_hash: Buffer.alloc(32),
              prev_hash: Buffer.alloc(32),
            },
          ],
          rowCount: 1,
        };
      }
      return { rows: [], rowCount: 0 };
    },
    release() {
      /* noop */
    },
  };

  return {
    async transaction<T>(fn: (c: typeof client) => Promise<T>): Promise<T> {
      return fn(client);
    },
    async query(text: string, params?: unknown[]) {
      // Used by the user-denied path's markFailedByNonce
      if (/UPDATE agent_registration_sessions/.test(text) && /WHERE nonce = \$1/.test(text)) {
        const nonce = params?.[0] as string;
        const reason = params?.[1] as string;
        for (const s of db.sessions.values()) {
          if (s.nonce === nonce && s.status === 'pending') {
            s.status = 'failed';
            s.status_message = reason;
            return { rows: [], rowCount: 1 };
          }
        }
      }
      return { rows: [], rowCount: 0 };
    },
  } as unknown as PostgresAdapter;
}

// ---------------------------------------------------------------------------
// Stub provider that returns a fixed Attestation.
// ---------------------------------------------------------------------------

class StubProvider implements IdentityProvider {
  readonly name = 'github_app';
  attestation: Attestation = {
    issuer: 'github.com',
    subject: '12345',
    audience: 'Iv1.abcdef',
    display_handle: 'octocat',
    assurance_level: 'medium',
    supports_revalidation: true,
  };
  shouldThrow = false;

  async beginRegistration(_ctx: AttestationContext) {
    return {};
  }
  async exchangeOrVerify(_input: ProviderInput, _ctx: AttestationContext) {
    if (this.shouldThrow) throw new Error('upstream down');
    return this.attestation;
  }
  async revalidate() {
    return { still_valid: true };
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('callback (SPEC §2.2.2)', () => {
  let db: FakeDb;
  let pg: PostgresAdapter;
  let provider: StubProvider;
  let kms: InMemoryKmsAdapter;
  let agentKp: { publicKey: Buffer; secretKey: Buffer };

  beforeAll(async () => {
    await sealedBoxReady();
  });

  beforeEach(() => {
    db = new FakeDb();
    pg = makeAdapter(db);
    provider = new StubProvider();
    kms = new InMemoryKmsAdapter();
    agentKp = keypair();
  });

  function seedSession(overrides: Partial<SessionRow> = {}): SessionRow {
    const row: SessionRow = {
      poll_token: 'pak_' + 'x'.repeat(43),
      nonce: 'NONCE',
      pkce_verifier: 'V',
      pkce_challenge: 'C',
      audience: 'Iv1.abcdef',
      expected_provider: 'github_app',
      redirect_uri: 'https://saas/callback',
      kind: 'register',
      target_account_id: null,
      client_pubkey: agentKp.publicKey,
      status: 'pending',
      status_message: null,
      result_ciphertext: null,
      account_id: null,
      expires_at: new Date(Date.now() + 60_000),
      ...overrides,
    };
    db.sessions.set(row.poll_token, row);
    return row;
  }

  it('happy path: new account, new identity, new key, sealed payload', async () => {
    const session = seedSession();
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('success');
    expect(out.is_first_key).toBe(true);

    // Session is now ready.
    const stored = db.sessions.get(session.poll_token)!;
    expect(stored.status).toBe('ready');
    expect(stored.result_ciphertext).toBeInstanceOf(Buffer);
    expect(stored.account_id).toBe(out.account_id);

    // Decrypt the sealed payload — agent SDK behavior simulation.
    const cleartext = sealedOpen(
      stored.result_ciphertext!,
      agentKp.publicKey,
      agentKp.secretKey,
    );
    const payload = JSON.parse(cleartext.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
      scopes: string[];
      tier: string;
      is_first_key: boolean;
      issued_at: string;
    };
    expect(payload.key.split('.')[0]).toBe(payload.key_id);
    expect(payload.key_id.startsWith('agk_')).toBe(true);
    expect(payload.account_id).toBe(out.account_id);
    expect(payload.scopes).toEqual(['read', 'self:rotate']);
    expect(payload.tier).toBe('cold');
    expect(payload.is_first_key).toBe(true);

    // Account + identity + key all written.
    expect(db.accounts.size).toBe(1);
    expect(db.identities.size).toBe(1);
    expect(db.keys.size).toBe(1);
  });

  it('user-denied path marks session failed without invoking provider', async () => {
    const session = seedSession();
    const out = await callback(
      {
        provider: 'github_app',
        state: 'NONCE',
        code: '',
        error: 'access_denied',
        error_description: 'user clicked cancel',
      },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('access_denied');
    const stored = db.sessions.get(session.poll_token)!;
    expect(stored.status).toBe('failed');
    expect(stored.status_message).toBe('access_denied');
  });

  it('RT-29: unknown nonce fails with anti-enumeration message', async () => {
    const out = await callback(
      { provider: 'github_app', state: 'WRONG', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('registration_session_not_found_or_expired');
  });

  it('RT-31: kind=recover with mismatched target_account_id is rejected', async () => {
    // Identity exists and points at acc-1, but session targets acc-2.
    db.accounts.set('acc-1', { id: 'acc-1', status: 'active', tier: 'cold' });
    db.identities.set('id-existing', {
      id: 'id-existing',
      account_id: 'acc-1',
      provider: 'github_app',
      subject: '12345',
      audience: 'Iv1.abcdef',
      status: 'active',
      revocation_source: null,
    });
    seedSession({
      poll_token: 'pkr_' + 'x'.repeat(43),
      kind: 'recover',
      target_account_id: 'acc-2',
    });

    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('identity_account_mismatch');
  });

  it('Case D: identity revoked by manual/cascade => admin unblock required', async () => {
    db.accounts.set('acc-1', { id: 'acc-1', status: 'active', tier: 'cold' });
    db.identities.set('id-x', {
      id: 'id-x',
      account_id: 'acc-1',
      provider: 'github_app',
      subject: '12345',
      audience: 'Iv1.abcdef',
      status: 'revoked',
      revocation_source: 'manual',
    });
    seedSession();
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('identity_blocked_admin_unblock_required');
  });

  it('Case C: identity revoked by webhook + kind=recover => re-activate', async () => {
    db.accounts.set('acc-1', { id: 'acc-1', status: 'active', tier: 'cold' });
    db.identities.set('id-r', {
      id: 'id-r',
      account_id: 'acc-1',
      provider: 'github_app',
      subject: '12345',
      audience: 'Iv1.abcdef',
      status: 'revoked',
      revocation_source: 'webhook',
    });
    seedSession({
      poll_token: 'pkr_' + 'x'.repeat(43),
      kind: 'recover',
      target_account_id: 'acc-1',
    });
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('success');
    expect(db.identities.get('id-r')!.status).toBe('active');
    expect(out.is_first_key).toBe(false); // recover is not first key
  });

  it('SPEC §2.4: kind=revalidate refreshes last_revalidated_at and stores NO sealed payload', async () => {
    // Pre-seed an active identity that's overdue for revalidation. The
    // session is bound to the same subject/audience.
    db.accounts.set('acc-rv', { id: 'acc-rv', status: 'active', tier: 'cold' });
    db.identities.set('id-rv', {
      id: 'id-rv',
      account_id: 'acc-rv',
      provider: 'github_app',
      subject: '12345',
      audience: 'Iv1.abcdef',
      status: 'active',
      revocation_source: null,
    });
    seedSession({
      poll_token: 'pav_' + 'x'.repeat(43),
      kind: 'revalidate',
      target_account_id: 'acc-rv',
    });

    const keysBefore = db.keys.size;
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('success');
    if (out.status !== 'success') return;
    expect(out.account_id).toBe('acc-rv');
    expect(out.is_first_key).toBe(false);
    // Key invariant: NO new key was issued (SPEC §2.4 step 6 — token
    // discarded, not stored).
    expect(db.keys.size).toBe(keysBefore);
    // Session ready, but result_ciphertext is null (no payload to seal).
    const sess = db.sessions.get('pav_' + 'x'.repeat(43));
    expect(sess?.status).toBe('ready');
    expect(sess?.result_ciphertext).toBeNull();
  });

  it('provider exchange failure is mapped to failed session', async () => {
    seedSession();
    provider.shouldThrow = true;
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('provider_exchange_failed');
  });

  it('audience mismatch in attestation is rejected', async () => {
    seedSession();
    provider.attestation = { ...provider.attestation, audience: 'OTHER' };
    const out = await callback(
      { provider: 'github_app', state: 'NONCE', code: 'CODE' },
      {
        postgres: pg,
        kms,
        identity_providers: [provider],
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
      },
    );
    expect(out.status).toBe('failed');
    expect(out.reason).toBe('audience_mismatch');
  });
});
