import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import { rotateKey } from '../../src/routes/rotate-key.js';
import { buildAgentContext } from '../../src/agent-context.js';
import { open as sealedOpen, sealedBoxReady, keypair } from '../../src/crypto/sealed-box.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { AgentContext, KeyCache } from '../../src/types.js';

interface OldKeyRow {
  id: string;
  key_id: string;
  account_id: string;
  issued_via_identity_id: string;
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  scopes: string[];
  tier: 'cold' | 'warm' | 'hot';
  expires_at: Date | null;
  rotated_at?: Date;
  rotation_grace_expires_at?: Date | null;
  revoked_at?: Date | null;
  replaced_by_key_id?: string | null;
  created_by_key_id?: string | null;
}

interface NewKeyRow {
  id: string;
  key_id: string;
  account_id: string;
  issued_via_identity_id: string;
  scopes: string[];
  tier: 'cold' | 'warm' | 'hot';
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  created_at: Date;
  created_by_key_id: string | null;
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
  keys = new Map<string, OldKeyRow>();
  newKeys = new Map<string, NewKeyRow>();
  idempotency = new Map<string, IdemRow>();
  epoch = 0;
  revocation_log: Array<Record<string, unknown>> = [];
  keyRowCounter = 0;
  keyIdCounter = 0;

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
    return { rows: [], rowCount: 1 };
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

  // Fetch old key row.
  if (/SELECT id, key_id, account_id, issued_via_identity_id, rotation_state/.test(text)) {
    const row = db.keys.get(params[0] as string);
    return { rows: row ? [row as unknown as R] : [], rowCount: row ? 1 : 0 };
  }
  // INSERT new key.
  if (/INSERT INTO agent_api_keys/.test(text)) {
    const [
      account_id,
      issued_via_identity_id,
      key_id,
      _key_hash,
      _key_pepper_version,
      _prefix,
      _label,
      scopes,
      tier,
      created_by_key_id,
      _expires_at,
    ] = params as [
      string,
      string,
      string,
      Buffer,
      number,
      string,
      string | null,
      string[],
      'cold' | 'warm' | 'hot',
      string | null,
      Date | null,
    ];
    const id = `row-${++db.keyRowCounter}`;
    const created_at = new Date();
    db.newKeys.set(id, {
      id,
      key_id,
      account_id,
      issued_via_identity_id,
      scopes,
      tier,
      rotation_state: 'active',
      created_at,
      created_by_key_id,
    });
    // Trigger: enforce_rotation_inverse — set old.replaced_by_key_id
    if (created_by_key_id) {
      for (const k of db.keys.values()) {
        if (k.id === created_by_key_id) {
          if (k.replaced_by_key_id) {
            const e = new Error('rotation_inverse_violation') as Error & { code: string };
            e.code = '23505'; // unique_violation
            throw e;
          }
          k.replaced_by_key_id = id;
        }
      }
    }
    return { rows: [{ id, created_at }] as unknown as R[], rowCount: 1 };
  }
  // UPDATE old key (rotation: rotating)
  if (/rotation_state = 'rotating'/.test(text)) {
    const idVal = params[0] as string;
    for (const k of db.keys.values()) {
      if (k.id === idVal) {
        k.rotation_state = 'rotating';
        k.rotated_at = new Date();
        k.rotation_grace_expires_at = new Date(
          Date.now() + Number(params[1]) * 1000,
        );
        return {
          rows: [
            { rotated_at: k.rotated_at, grace: k.rotation_grace_expires_at },
          ] as unknown as R[],
          rowCount: 1,
        };
      }
    }
    return { rows: [], rowCount: 0 };
  }
  // UPDATE old key (emergency: revoked + grace=now())
  if (/rotation_state = 'revoked'/.test(text)) {
    const idVal = params[0] as string;
    for (const k of db.keys.values()) {
      if (k.id === idVal) {
        k.rotation_state = 'revoked';
        k.rotated_at = new Date();
        k.rotation_grace_expires_at = new Date();
        k.revoked_at = new Date();
        return {
          rows: [
            { rotated_at: k.rotated_at, grace: k.rotation_grace_expires_at },
          ] as unknown as R[],
          rowCount: 1,
        };
      }
    }
    return { rows: [], rowCount: 0 };
  }
  // Epoch bump
  if (/UPDATE agent_revocation_epoch/.test(text)) {
    db.epoch += 1;
    return { rows: [{ epoch: String(db.epoch) }] as unknown as R[], rowCount: 1 };
  }
  if (/SELECT epoch::text AS epoch FROM agent_revocation_epoch/.test(text)) {
    return { rows: [{ epoch: String(db.epoch) }] as unknown as R[], rowCount: 1 };
  }
  if (/pg_current_wal_insert_lsn/.test(text)) {
    return { rows: [{ commit_lsn: '0/B1' }] as unknown as R[], rowCount: 1 };
  }
  if (/INSERT INTO agent_revocation_log/.test(text)) {
    db.revocation_log.push({
      kind: text.includes("'emergency_rotate'") ? 'emergency_rotate' : 'unknown',
      target_id: params[1],
      reason: params[4] ?? null,
    });
    return { rows: [], rowCount: 1 };
  }
  if (/INSERT INTO agent_audit_log/.test(text)) {
    return {
      rows: [
        {
          id: '1',
          ts: new Date(),
          row_hash: Buffer.alloc(32),
          prev_hash: Buffer.alloc(32),
        },
      ] as unknown as R[],
      rowCount: 1,
    };
  }
  if (/SET LOCAL synchronous_commit/.test(text) || /^(BEGIN|COMMIT|ROLLBACK|SET ROLE)/.test(text.trim())) {
    return { rows: [], rowCount: 0 };
  }
  return { rows: [], rowCount: 0 };
}

function ctx(scopes: string[] = ['self:rotate']): AgentContext {
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

function seedOld(db: FakeDb): OldKeyRow {
  const row: OldKeyRow = {
    id: 'row-old',
    key_id: 'agk_caller__',
    account_id: 'acc-1',
    issued_via_identity_id: 'id-1',
    rotation_state: 'active',
    scopes: ['read', 'self:rotate'],
    tier: 'cold',
    expires_at: null,
  };
  db.keys.set(row.key_id, row);
  return row;
}

describe('rotateKey (SPEC §2.7)', () => {
  let db: FakeDb;
  let redis: InMemoryRedisAdapter;
  let kms: InMemoryKmsAdapter;

  beforeAll(async () => {
    await sealedBoxReady();
  });

  beforeEach(() => {
    db = new FakeDb();
    redis = new InMemoryRedisAdapter();
    kms = new InMemoryKmsAdapter();
  });

  it('planned rotation: old=rotating with grace; new key issued; epoch bumped', async () => {
    seedOld(db);
    const out = await rotateKey(
      { grace_seconds: 3600, reason: 'scheduled_rotation' },
      {
        postgres: asAdapter(db),
        redis,
        kms,
        region: 'us-east-1',
        caller: ctx(),
        idempotency_key: 'idk_planned',
      },
    );
    expect(out.old_key.key_id).toBe('agk_caller__');
    expect(out.old_key.grace_expires_at).toMatch(/T/);
    expect(out.new_key.key_id.startsWith('agk_')).toBe(true);
    expect(out.new_key.secret).toBeDefined();
    expect(out.new_key.scopes).toEqual(['read', 'self:rotate']);
    expect(db.keys.get('agk_caller__')!.rotation_state).toBe('rotating');
    expect(db.keys.get('agk_caller__')!.replaced_by_key_id).toBeTruthy();
    expect(db.epoch).toBe(1);
  });

  it('emergency rotation: old=revoked immediately; epoch bumped; revocation_log appended', async () => {
    seedOld(db);
    const out = await rotateKey(
      { grace_seconds: 0, reason: 'compromised' },
      {
        postgres: asAdapter(db),
        redis,
        kms,
        region: 'us-east-1',
        caller: ctx(),
        idempotency_key: 'idk_emergency',
      },
    );
    expect(out.old_key.key_id).toBe('agk_caller__');
    expect(db.keys.get('agk_caller__')!.rotation_state).toBe('revoked');
    expect(db.keys.get('agk_caller__')!.revoked_at).toBeInstanceOf(Date);
    expect(db.revocation_log).toContainEqual(
      expect.objectContaining({ kind: 'emergency_rotate' }),
    );
  });

  it('rejects when caller lacks self:rotate', async () => {
    seedOld(db);
    await expect(
      rotateKey(
        { grace_seconds: 3600 },
        {
          postgres: asAdapter(db),
          redis,
          kms,
          region: 'us-east-1',
          caller: ctx([]),
          idempotency_key: 'idk_scope',
        },
      ),
    ).rejects.toMatchObject({ status: 403, code: 'insufficient_scope' });
  });

  it('returns 409 already_rotating if old key is in rotating state', async () => {
    const old = seedOld(db);
    old.rotation_state = 'rotating';
    await expect(
      rotateKey(
        { grace_seconds: 3600 },
        {
          postgres: asAdapter(db),
          redis,
          kms,
          region: 'us-east-1',
          caller: ctx(),
          idempotency_key: 'idk_already',
        },
      ),
    ).rejects.toMatchObject({ status: 409, code: 'already_rotating' });
  });

  it('returns 401 key_revoked when old key already revoked', async () => {
    const old = seedOld(db);
    old.rotation_state = 'revoked';
    await expect(
      rotateKey(
        { grace_seconds: 3600 },
        {
          postgres: asAdapter(db),
          redis,
          kms,
          region: 'us-east-1',
          caller: ctx(),
          idempotency_key: 'idk_revoked',
        },
      ),
    ).rejects.toMatchObject({ status: 401, code: 'key_revoked' });
  });

  it('returns sealed-box payload when client_pubkey_b64 supplied', async () => {
    seedOld(db);
    const kp = keypair();
    const out = await rotateKey(
      { grace_seconds: 3600, client_pubkey_b64: kp.publicKey.toString('base64url') },
      {
        postgres: asAdapter(db),
        redis,
        kms,
        region: 'us-east-1',
        caller: ctx(),
        idempotency_key: 'idk_sealed',
      },
    );
    expect(out.new_key.encrypted_payload).toBeDefined();
    expect(out.new_key.secret).toBeUndefined();
    const cleartext = sealedOpen(
      Buffer.from(out.new_key.encrypted_payload!, 'base64url'),
      kp.publicKey,
      kp.secretKey,
    );
    const payload = JSON.parse(cleartext.toString('utf8')) as {
      key: string;
      key_id: string;
      account_id: string;
      is_first_key: boolean;
    };
    expect(payload.key_id).toBe(out.new_key.key_id);
    expect(payload.account_id).toBe('acc-1');
    expect(payload.is_first_key).toBe(false);
  });

  it('idempotent emergency rotation replays cached response', async () => {
    seedOld(db);
    const args = { grace_seconds: 0, reason: 'compromised' };
    const deps = {
      postgres: asAdapter(db),
      redis,
      kms,
      region: 'us-east-1',
      caller: ctx(),
      idempotency_key: 'idk_emergency_replay',
    };
    const first = await rotateKey(args, deps);
    const epochBefore = db.epoch;
    const second = await rotateKey(args, deps);
    expect(second.new_key.key_id).toBe(first.new_key.key_id);
    expect(db.epoch).toBe(epochBefore);
  });
});
