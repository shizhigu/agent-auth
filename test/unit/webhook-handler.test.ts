import { describe, it, expect, beforeEach } from 'vitest';
import { createHmac } from 'node:crypto';
import { GitHubAppProvider } from '../../src/identity/github-app/browser-flow.js';
import { handleWebhookRequest } from '../../src/routes/webhooks.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface IdentityRow {
  id: string;
  account_id: string;
  status: 'active' | 'revoked' | 'expired';
  is_primary: boolean;
}
interface KeyRow {
  id: string;
  key_id: string;
  account_id: string;
  issued_via_identity_id: string;
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
}
interface AccountRow {
  id: string;
  status: 'active' | 'suspended' | 'closed';
}
interface WebhookEventRow {
  id: string;
  payload_hash: Buffer;
  status: string;
}

class FakeDb {
  identities = new Map<string, IdentityRow>();
  keys = new Map<string, KeyRow>();
  accounts = new Map<string, AccountRow>();
  events = new Map<string, WebhookEventRow>();
  epoch = 0;
  revocation_log: Array<{ kind: string; target_id: string }> = [];

  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    return runQuery<R>(this, text, params);
  }
  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    const out = await runQuery<R>(this, text, params);
    return (out.rows[0] as R) ?? null;
  }
  async transaction<T>(fn: (c: FakeDb) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

function runQuery<R>(
  db: FakeDb,
  text: string,
  params: ReadonlyArray<unknown>,
): { rows: R[]; rowCount: number } {
  // Atomic INSERT for webhook event
  if (/INSERT INTO agent_webhook_events/.test(text)) {
    const [id, _provider, _event_type, payload_hash] = params as [
      string,
      string,
      string,
      Buffer,
    ];
    if (db.events.has(id)) {
      return { rows: [{ inserted: false } as unknown as R], rowCount: 1 };
    }
    db.events.set(id, { id, payload_hash, status: 'received' });
    return { rows: [{ inserted: true } as unknown as R], rowCount: 1 };
  }
  if (/SELECT payload_hash, status FROM agent_webhook_events/.test(text)) {
    const row = db.events.get(params[0] as string);
    return { rows: row ? [row as unknown as R] : [], rowCount: row ? 1 : 0 };
  }
  if (/UPDATE agent_webhook_events/.test(text)) {
    const r = db.events.get(params[0] as string);
    if (r) r.status = text.includes("'processed'") ? 'processed' : 'failed';
    return { rows: [], rowCount: r ? 1 : 0 };
  }
  // Identity
  if (/SELECT id, account_id, status FROM agent_identities/.test(text)) {
    const [provider, subject] = params as [string, string];
    void provider;
    for (const v of db.identities.values()) {
      if (v.status === 'active' && /* by subject implicit */ true && subject) {
        return { rows: [v as unknown as R], rowCount: 1 };
      }
    }
    return { rows: [], rowCount: 0 };
  }
  if (/UPDATE agent_identities/.test(text) && /SET status = 'revoked'/.test(text)) {
    const idVal = params[0] as string;
    const r = db.identities.get(idVal);
    if (r) r.status = 'revoked';
    return { rows: [], rowCount: r ? 1 : 0 };
  }
  // Cascade UPDATE keys
  if (/UPDATE agent_api_keys[\s\S]+rotation_state = 'revoked'/.test(text) && /WHERE issued_via_identity_id/.test(text)) {
    const idVal = params[0] as string;
    const out: KeyRow[] = [];
    for (const k of db.keys.values()) {
      if (
        k.issued_via_identity_id === idVal &&
        (k.rotation_state === 'active' || k.rotation_state === 'rotating')
      ) {
        k.rotation_state = 'revoked';
        out.push(k);
      }
    }
    return { rows: out as unknown as R[], rowCount: out.length };
  }
  if (/SELECT count\(\*\)::text AS count FROM agent_identities/.test(text)) {
    const [account_id] = params as [string];
    const count = [...db.identities.values()].filter(
      (i) => i.account_id === account_id && i.status === 'active' && i.is_primary,
    ).length;
    return { rows: [{ count: String(count) } as unknown as R], rowCount: 1 };
  }
  if (/UPDATE agent_accounts/.test(text) && /SET status = 'suspended'/.test(text)) {
    const id = params[0] as string;
    const a = db.accounts.get(id);
    if (a && a.status === 'active') a.status = 'suspended';
    return { rows: [], rowCount: a ? 1 : 0 };
  }
  if (/UPDATE agent_revocation_epoch/.test(text)) {
    db.epoch++;
    return { rows: [{ epoch: String(db.epoch) } as unknown as R], rowCount: 1 };
  }
  if (/pg_current_wal_insert_lsn/.test(text)) {
    return { rows: [{ commit_lsn: '0/AB12' } as unknown as R], rowCount: 1 };
  }
  if (/INSERT INTO agent_revocation_log/.test(text)) {
    db.revocation_log.push({
      kind: text.includes("'identity_revoke'") ? 'identity_revoke' : 'unknown',
      target_id: params[1] as string,
    });
    return { rows: [], rowCount: 1 };
  }
  if (/SET LOCAL synchronous_commit/.test(text) || /^(BEGIN|COMMIT|ROLLBACK|SET ROLE)/.test(text.trim())) {
    return { rows: [], rowCount: 0 };
  }
  if (/UPDATE agent_revocation_barrier/.test(text)) {
    return { rows: [], rowCount: 1 };
  }
  return { rows: [], rowCount: 0 };
}

function asAdapter(d: FakeDb): PostgresAdapter {
  return d as unknown as PostgresAdapter;
}

function gh_signature(secret: string, body: Buffer): string {
  return 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
}

function fakeUuid(seed: number): string {
  // Deterministic UUID-shaped string.
  return `00000000-0000-0000-0000-${String(seed).padStart(12, '0')}`;
}

const SECRET = 'super-secret';
const PROVIDER_CFG = {
  client_id: 'Iv1.abcdef',
  client_secret: 'cs',
  webhook_secret: SECRET,
};

function makeProvider(cfgOverride: Partial<typeof PROVIDER_CFG & { webhook_secret_previous: string }> = {}) {
  return new GitHubAppProvider({ ...PROVIDER_CFG, ...cfgOverride });
}

function makeBody(action = 'revoked', subject = 12345) {
  return Buffer.from(
    JSON.stringify({
      action,
      sender: { id: subject, login: 'octocat' },
    }),
    'utf8',
  );
}

describe('handleWebhookRequest (SPEC §2.2.4)', () => {
  let db: FakeDb;
  let redis: InMemoryRedisAdapter;

  beforeEach(() => {
    db = new FakeDb();
    redis = new InMemoryRedisAdapter();
    db.accounts.set('acc-1', { id: 'acc-1', status: 'active' });
    db.identities.set('id-1', { id: 'id-1', account_id: 'acc-1', status: 'active', is_primary: true });
    db.keys.set('agk_a__', {
      id: 'row-a',
      key_id: 'agk_a__',
      account_id: 'acc-1',
      issued_via_identity_id: 'id-1',
      rotation_state: 'active',
    });
    db.keys.set('agk_b__', {
      id: 'row-b',
      key_id: 'agk_b__',
      account_id: 'acc-1',
      issued_via_identity_id: 'id-1',
      rotation_state: 'rotating',
    });
  });

  it('happy path: HMAC verifies, identity revoked, keys cascaded, account suspended, epoch bumped', async () => {
    const body = makeBody();
    const id = fakeUuid(1);
    const result = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': gh_signature(SECRET, body),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': id,
        },
        raw_body: body,
      },
      {
        postgres: asAdapter(db),
        redis,
        identity_providers: [makeProvider()],
        region: 'us-east-1',
      },
    );
    expect(result.status).toBe('processed');
    expect(new Set(result.invalidated_keys)).toEqual(new Set(['agk_a__', 'agk_b__']));
    expect(db.identities.get('id-1')!.status).toBe('revoked');
    expect(db.keys.get('agk_a__')!.rotation_state).toBe('revoked');
    expect(db.keys.get('agk_b__')!.rotation_state).toBe('revoked');
    expect(db.accounts.get('acc-1')!.status).toBe('suspended');
    expect(db.epoch).toBe(1);
    expect(db.revocation_log[0]?.kind).toBe('identity_revoke');
    expect(db.events.get(id)!.status).toBe('processed');
  });

  it('rejects with 401-ish when HMAC is invalid', async () => {
    const body = makeBody();
    await expect(
      handleWebhookRequest(
        {
          provider: 'github_app',
          headers: {
            'x-hub-signature-256': 'sha256=' + 'a'.repeat(64),
            'x-github-event': 'github_app_authorization',
            'x-github-delivery': fakeUuid(2),
          },
          raw_body: body,
        },
        {
          postgres: asAdapter(db),
          redis,
          identity_providers: [makeProvider()],
          region: 'us-east-1',
        },
      ),
    ).rejects.toMatchObject({ status: 401 });
    // No DB write because verify fails BEFORE dedup INSERT.
    expect(db.events.size).toBe(0);
  });

  it('RT-6 replay: duplicate delivery is idempotent (status=duplicate, no extra revocation)', async () => {
    const body = makeBody();
    const id = fakeUuid(3);
    const deps = {
      postgres: asAdapter(db),
      redis,
      identity_providers: [makeProvider()],
      region: 'us-east-1',
    };
    const headers = {
      'x-hub-signature-256': gh_signature(SECRET, body),
      'x-github-event': 'github_app_authorization',
      'x-github-delivery': id,
    };
    await handleWebhookRequest({ provider: 'github_app', headers, raw_body: body }, deps);
    const epochBefore = db.epoch;
    const second = await handleWebhookRequest(
      { provider: 'github_app', headers, raw_body: body },
      deps,
    );
    expect(second.status).toBe('duplicate');
    expect(db.epoch).toBe(epochBefore);
  });

  it('RT-30 collision: same delivery id, different body raises onAlert; existing row wins', async () => {
    const body1 = makeBody('revoked');
    const body2 = makeBody('revoked', 99999); // different sender
    const id = fakeUuid(4);
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const deps = {
      postgres: asAdapter(db),
      redis,
      identity_providers: [makeProvider()],
      region: 'us-east-1',
      onAlert: (label: string, meta: Record<string, unknown>) =>
        alerts.push({ label, meta }),
    };
    await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': gh_signature(SECRET, body1),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': id,
        },
        raw_body: body1,
      },
      deps,
    );
    await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': gh_signature(SECRET, body2),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': id,
        },
        raw_body: body2,
      },
      deps,
    );
    expect(alerts).toContainEqual(
      expect.objectContaining({ label: 'webhook_id_collision_with_payload_mismatch' }),
    );
  });

  it('RT-42 dual-secret: webhook_secret_previous is accepted during rotation', async () => {
    const body = makeBody();
    const result = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': gh_signature('OLD_SECRET', body),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': fakeUuid(5),
        },
        raw_body: body,
      },
      {
        postgres: asAdapter(db),
        redis,
        identity_providers: [
          makeProvider({ webhook_secret: 'NEW_SECRET', webhook_secret_previous: 'OLD_SECRET' }),
        ],
        region: 'us-east-1',
      },
    );
    expect(result.status).toBe('processed');
  });

  it('non-revoked event types are processed but produce no actions', async () => {
    const body = Buffer.from(
      JSON.stringify({ action: 'created', sender: { id: 12345 } }),
      'utf8',
    );
    const result = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': gh_signature(SECRET, body),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': fakeUuid(6),
        },
        raw_body: body,
      },
      {
        postgres: asAdapter(db),
        redis,
        identity_providers: [makeProvider()],
        region: 'us-east-1',
      },
    );
    expect(result.status).toBe('ignored');
    expect(db.identities.get('id-1')!.status).toBe('active');
    expect(db.epoch).toBe(0);
  });

  it('returns 404 for unknown provider', async () => {
    await expect(
      handleWebhookRequest(
        {
          provider: 'unknown',
          headers: {},
          raw_body: Buffer.from('{}'),
        },
        {
          postgres: asAdapter(db),
          redis,
          identity_providers: [makeProvider()],
          region: 'us-east-1',
        },
      ),
    ).rejects.toMatchObject({ status: 404 });
  });
});
