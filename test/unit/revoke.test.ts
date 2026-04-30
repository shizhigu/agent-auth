import { describe, it, expect, beforeEach } from 'vitest';
import { revoke } from '../../src/routes/revoke.js';
import { buildAgentContext } from '../../src/agent-context.js';
import { InMemoryRedisAdapter, KEY_PREFIX_KEY } from '../../src/storage/redis-adapter.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { AgentContext, KeyCache } from '../../src/types.js';

// ---------------------------------------------------------------------------
// Fake Postgres model — supports the queries revoke + tierBIdempotent issue
// ---------------------------------------------------------------------------

interface KeyRow {
  id: string;
  key_id: string;
  account_id: string;
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  revoked_at: Date | null;
  last_revoke_lsn: string | null;
}

interface IdemRow {
  key: string;
  request_hash: Buffer;
  operation_type: string;
  resource_ref: string;
  state: 'pending' | 'completed' | 'failed' | 'unknown' | 'manual_required';
  outcome_status: number | null;
  outcome_body: unknown;
  reconcile_attempts: number;
  expires_at: Date;
  created_at: Date;
}

class FakeDb {
  keys = new Map<string, KeyRow>();
  idempotency = new Map<string, IdemRow>();
  epoch = 0;
  revocation_log: Array<{
    region: string;
    kind: string;
    target_id: string;
    commit_lsn: string;
    epoch: number;
    reason: string | null;
  }> = [];
  audit_log: Array<{
    event_type: string;
    account_id: string | null;
    key_id: string | null;
    meta: Record<string, unknown> | null;
  }> = [];

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
  // Idempotency rows
  if (/SELECT \* FROM agent_idempotency WHERE key = \$1 FOR UPDATE/.test(text)) {
    const row = db.idempotency.get(params[0] as string);
    return { rows: row ? [row as unknown as R] : [], rowCount: row ? 1 : 0 };
  }
  if (/INSERT INTO agent_idempotency/.test(text)) {
    const [key, request_hash, operation_type, resource_ref] = params as [
      string,
      Buffer,
      string,
      string,
    ];
    // INSERT ... ON CONFLICT (key) DO NOTHING RETURNING (xmax = 0)
    if (db.idempotency.has(key)) {
      return { rows: [], rowCount: 0 };
    }
    db.idempotency.set(key, {
      key,
      request_hash,
      operation_type,
      resource_ref,
      state: 'pending',
      outcome_status: null,
      outcome_body: null,
      reconcile_attempts: 0,
      expires_at: new Date(Date.now() + 24 * 3600 * 1000),
      created_at: new Date(),
    });
    return { rows: [{ inserted: true } as unknown as R], rowCount: 1 };
  }
  if (/UPDATE agent_idempotency/.test(text) && /SET state = 'completed'/.test(text)) {
    const r = db.idempotency.get(params[0] as string);
    if (r) {
      r.state = 'completed';
      r.outcome_status = params[1] as number;
      r.outcome_body = JSON.parse(params[2] as string);
    }
    return { rows: [], rowCount: r ? 1 : 0 };
  }
  if (/UPDATE agent_idempotency/.test(text) && /SET state = 'failed'/.test(text)) {
    const r = db.idempotency.get(params[0] as string);
    if (r && r.state === 'pending') {
      r.state = 'failed';
      r.outcome_status = params[1] as number;
      r.outcome_body = JSON.parse(params[2] as string);
    }
    return { rows: [], rowCount: r ? 1 : 0 };
  }

  // Key row select
  if (/SELECT id, key_id, account_id, rotation_state, revoked_at\s+FROM agent_api_keys/.test(text)) {
    const row = db.keys.get(params[0] as string);
    return { rows: row ? [row as unknown as R] : [], rowCount: row ? 1 : 0 };
  }
  // Key UPDATE → revoked
  if (/UPDATE agent_api_keys[\s\S]+rotation_state = 'revoked'/.test(text) && /WHERE id = \$1/.test(text)) {
    const idVal = params[0] as string;
    for (const k of db.keys.values()) {
      if (k.id === idVal) {
        k.rotation_state = 'revoked';
        k.revoked_at = new Date();
        return { rows: [{ revoked_at: k.revoked_at }] as unknown as R[], rowCount: 1 };
      }
    }
    return { rows: [], rowCount: 0 };
  }
  // last_revoke_lsn UPDATE
  if (/UPDATE agent_api_keys SET last_revoke_lsn/.test(text)) {
    const idVal = params[0] as string;
    for (const k of db.keys.values()) {
      if (k.id === idVal) k.last_revoke_lsn = params[1] as string;
    }
    return { rows: [], rowCount: 1 };
  }
  // Epoch bump
  if (/UPDATE agent_revocation_epoch/.test(text)) {
    db.epoch += 1;
    return { rows: [{ epoch: String(db.epoch) }] as unknown as R[], rowCount: 1 };
  }
  // pg_current_wal_insert_lsn
  if (/pg_current_wal_insert_lsn/.test(text)) {
    return { rows: [{ commit_lsn: '0/A1B2' }] as unknown as R[], rowCount: 1 };
  }
  // revocation_log insert
  if (/INSERT INTO agent_revocation_log/.test(text)) {
    db.revocation_log.push({
      region: params[0] as string,
      kind: text.includes("'key_revoke'") ? 'key_revoke' : 'unknown',
      target_id: params[1] as string,
      commit_lsn: params[2] as string,
      epoch: params[3] as number,
      reason: (params[4] as string | null) ?? null,
    });
    return { rows: [], rowCount: 1 };
  }
  // audit_log insert (writeAuditRowOnClient) — return a fake row so the
  // helper's RETURNING clause is satisfied. Real schema invariants are
  // covered by integration tests against the live trigger.
  if (/INSERT INTO agent_audit_log/.test(text)) {
    db.audit_log.push({
      event_type: params[4] as string,
      account_id: (params[1] as string) ?? null,
      key_id: (params[2] as string) ?? null,
      meta: params[11] ? JSON.parse(params[11] as string) : null,
    });
    return {
      rows: [
        {
          id: String(db.audit_log.length),
          ts: new Date(),
          row_hash: Buffer.alloc(32),
          prev_hash: Buffer.alloc(32),
        },
      ] as unknown as R[],
      rowCount: 1,
    };
  }
  // SET LOCAL synchronous_commit
  if (/SET LOCAL synchronous_commit/.test(text)) {
    return { rows: [], rowCount: 0 };
  }
  // BEGIN/COMMIT/ROLLBACK
  if (/^(BEGIN|COMMIT|ROLLBACK|SET ROLE)/.test(text.trim())) {
    return { rows: [], rowCount: 0 };
  }
  return { rows: [], rowCount: 0 };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ctx(scopes: string[] = ['self:revoke']): AgentContext {
  const cache: KeyCache = {
    key_id: 'agk_caller__',
    account_id: 'acc-1',
    account_status: 'active',
    issuing_identity_id: 'id-1',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: '12345',
    identity_assurance_level: 'medium',
    key_hash: Buffer.alloc(32),
    key_pepper_version: 1,
    scopes,
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    grace_expires_at: null,
    expires_at: null,
    cached_epoch: 0,
    cached_at: 0,
    redis_expires_at: 30000,
  };
  return buildAgentContext(cache);
}

function asAdapter(d: FakeDb): PostgresAdapter {
  return d as unknown as PostgresAdapter;
}

function seedKey(db: FakeDb, key_id: string, account_id = 'acc-1'): KeyRow {
  const row: KeyRow = {
    id: `row-${key_id}`,
    key_id,
    account_id,
    rotation_state: 'active',
    revoked_at: null,
    last_revoke_lsn: null,
  };
  db.keys.set(key_id, row);
  return row;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('revoke (SPEC §2.8)', () => {
  let db: FakeDb;
  let redis: InMemoryRedisAdapter;

  beforeEach(() => {
    db = new FakeDb();
    redis = new InMemoryRedisAdapter();
  });

  it('happy path: self-revoke flips key to revoked and bumps epoch', async () => {
    seedKey(db, 'agk_caller__');
    await redis.set(KEY_PREFIX_KEY + 'agk_caller__', '{"x":1}');
    const out = await revoke(
      { key_id: 'agk_caller__', reason: 'lost_device' },
      {
        postgres: asAdapter(db),
        redis,
        region: 'us-east-1',
        caller: ctx(['self:revoke']),
        idempotency_key: 'idk_1',
      },
    );
    expect(out.key_id).toBe('agk_caller__');
    expect(out.revoked_at).toMatch(/T/);
    expect(db.keys.get('agk_caller__')!.rotation_state).toBe('revoked');
    expect(db.epoch).toBe(1);
    expect(db.revocation_log).toHaveLength(1);
    expect(db.revocation_log[0]!.kind).toBe('key_revoke');
    expect(await redis.get(KEY_PREFIX_KEY + 'agk_caller__')).toBeNull();
  });

  it('idempotent replay returns the same response without re-running operation', async () => {
    seedKey(db, 'agk_caller__');
    const args = {
      key_id: 'agk_caller__',
      reason: 'lost_device',
    };
    const deps = {
      postgres: asAdapter(db),
      redis,
      region: 'us-east-1',
      caller: ctx(['self:revoke']),
      idempotency_key: 'idk_replay',
    };
    const first = await revoke(args, deps);
    const epochBefore = db.epoch;
    const second = await revoke(args, deps);
    expect(second).toEqual(first);
    expect(db.epoch).toBe(epochBefore); // operation NOT re-run
  });

  it('replay with different payload returns 409 idempotency_key_payload_mismatch', async () => {
    seedKey(db, 'agk_caller__');
    const deps = {
      postgres: asAdapter(db),
      redis,
      region: 'us-east-1',
      caller: ctx(['self:revoke']),
      idempotency_key: 'idk_mm',
    };
    await revoke({ key_id: 'agk_caller__', reason: 'a' }, deps);
    await expect(
      revoke({ key_id: 'agk_caller__', reason: 'different' }, deps),
    ).rejects.toMatchObject({ status: 409, code: 'idempotency_key_payload_mismatch' });
  });

  it('admin:keys + missing key on caller account returns 404', async () => {
    await expect(
      revoke(
        { key_id: 'agk_missing_' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx(['admin:keys']),
          idempotency_key: 'idk_404',
        },
      ),
    ).rejects.toMatchObject({ status: 404, code: 'key_not_found' });
  });

  it('admin:keys + cross-account key returns 404 (anti-enumeration)', async () => {
    seedKey(db, 'agk_other___', 'acc-other');
    await expect(
      revoke(
        { key_id: 'agk_other___' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx(['admin:keys']),
          idempotency_key: 'idk_xacc',
        },
      ),
    ).rejects.toMatchObject({ status: 404, code: 'key_not_found' });
  });

  it('self:revoke targeting another key (without admin:keys) returns 403', async () => {
    // Pre-auth scope check fires before any DB lookup, so we can't see whether
    // the key exists. Caller without admin:keys is forbidden from revoking
    // anything but their own key.
    await expect(
      revoke(
        { key_id: 'agk_other___' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx(['self:revoke']),
          idempotency_key: 'idk_scope_other',
        },
      ),
    ).rejects.toMatchObject({ status: 403, code: 'insufficient_scope' });
  });

  it('returns 403 insufficient_scope when caller lacks required scope', async () => {
    seedKey(db, 'agk_caller__');
    await expect(
      revoke(
        { key_id: 'agk_caller__' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx([]),
          idempotency_key: 'idk_scope',
        },
      ),
    ).rejects.toMatchObject({ status: 403, code: 'insufficient_scope' });
  });

  it('admin:keys can revoke another key on the same account', async () => {
    seedKey(db, 'agk_caller__');
    seedKey(db, 'agk_other___'); // same account
    const out = await revoke(
      { key_id: 'agk_other___' },
      {
        postgres: asAdapter(db),
        redis,
        region: 'us-east-1',
        caller: ctx(['admin:keys']),
        idempotency_key: 'idk_admin',
      },
    );
    expect(out.key_id).toBe('agk_other___');
    expect(db.keys.get('agk_other___')!.rotation_state).toBe('revoked');
  });

  it('rejects requests without an Idempotency-Key', async () => {
    seedKey(db, 'agk_caller__');
    await expect(
      revoke(
        { key_id: 'agk_caller__' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx(['self:revoke']),
          idempotency_key: '',
        },
      ),
    ).rejects.toMatchObject({ status: 400 });
  });

  it('rejects malformed body', async () => {
    await expect(
      revoke(
        { key_id: 'NOT_A_KEY_ID' },
        {
          postgres: asAdapter(db),
          redis,
          region: 'us-east-1',
          caller: ctx(['self:revoke']),
          idempotency_key: 'idk_bad',
        },
      ),
    ).rejects.toMatchObject({ status: 400 });
  });
});
