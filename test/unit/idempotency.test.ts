import { describe, it, expect, beforeEach } from 'vitest';
import {
  tierBIdempotent,
  canonicalRequestHash,
} from '../../src/reliability/idempotency.js';
import { TierBTimeoutError } from '../../src/distributed/tier-b-commit.js';
import { AgentAuthError, ServiceUnavailableError } from '../../src/errors.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

// ---------------------------------------------------------------------------
// FakePg: minimal model of agent_idempotency for the framework's queries
// ---------------------------------------------------------------------------

interface IdemRow {
  key: string;
  request_hash: Buffer;
  operation_type: string;
  resource_ref: string;
  outcome_status: number | null;
  outcome_body: unknown;
  state: 'pending' | 'completed' | 'failed' | 'unknown' | 'manual_required';
  reconcile_attempts: number;
  expires_at: Date;
  created_at: Date;
}

class FakeIdemPg {
  rows = new Map<string, IdemRow>();

  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    if (/SELECT \* FROM agent_idempotency WHERE key = \$1 FOR UPDATE/.test(text)) {
      const r = this.rows.get(params[0] as string);
      return { rows: r ? [r as unknown as R] : [], rowCount: r ? 1 : 0 };
    }
    if (/INSERT INTO agent_idempotency/.test(text)) {
      const [key, request_hash, operation_type, resource_ref] = params as [
        string,
        Buffer,
        string,
        string,
      ];
      const row: IdemRow = {
        key,
        request_hash,
        operation_type,
        resource_ref,
        outcome_status: null,
        outcome_body: null,
        state: 'pending',
        reconcile_attempts: 0,
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
        created_at: new Date(),
      };
      this.rows.set(key, row);
      return { rows: [], rowCount: 1 };
    }
    if (/UPDATE agent_idempotency/.test(text) && /SET state = 'completed'/.test(text)) {
      const [key, status, body] = params as [string, number, string];
      const r = this.rows.get(key);
      if (r) {
        r.state = 'completed';
        r.outcome_status = status;
        r.outcome_body = JSON.parse(body);
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/UPDATE agent_idempotency/.test(text) && /SET state = 'unknown'/.test(text)) {
      const [key] = params as [string];
      const r = this.rows.get(key);
      if (r && r.state === 'pending') r.state = 'unknown';
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/UPDATE agent_idempotency/.test(text) && /SET state = 'failed'/.test(text)) {
      const [key, status, body] = params as [string, number, string];
      const r = this.rows.get(key);
      if (r && r.state === 'pending') {
        r.state = 'failed';
        r.outcome_status = status;
        r.outcome_body = JSON.parse(body);
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    return { rows: [], rowCount: 0 };
  }

  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    const out = await this.query<R>(text, params);
    return (out.rows[0] as R) ?? null;
  }

  async transaction<T>(fn: (tx: FakeIdemPg) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

function asAdapter(p: FakeIdemPg): PostgresAdapter {
  return p as unknown as PostgresAdapter;
}

// ---------------------------------------------------------------------------
// canonicalRequestHash
// ---------------------------------------------------------------------------

describe('canonicalRequestHash', () => {
  it('is stable across object key order', () => {
    const a = canonicalRequestHash({ b: 1, a: 'x' });
    const b = canonicalRequestHash({ a: 'x', b: 1 });
    expect(a.equals(b)).toBe(true);
  });

  it('differs when payloads differ', () => {
    expect(
      canonicalRequestHash({ a: 'x' }).equals(canonicalRequestHash({ a: 'y' })),
    ).toBe(false);
  });

  it('preserves array order (semantically meaningful)', () => {
    expect(
      canonicalRequestHash({ scopes: ['a', 'b'] }).equals(
        canonicalRequestHash({ scopes: ['b', 'a'] }),
      ),
    ).toBe(false);
  });

  it('encodes Buffers as base64', () => {
    const b = canonicalRequestHash({ k: Buffer.from('hi') });
    const same = canonicalRequestHash({ k: Buffer.from('hi') });
    expect(b.equals(same)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// tierBIdempotent
// ---------------------------------------------------------------------------

describe('tierBIdempotent (SPEC §5.1.1)', () => {
  let pg: FakeIdemPg;

  beforeEach(() => {
    pg = new FakeIdemPg();
  });

  it('phase 2 runs operation and persists outcome on success', async () => {
    const out = await tierBIdempotent(
      asAdapter(pg),
      {
        idempotency_key: 'idk_1',
        request_hash: canonicalRequestHash({ a: 1 }),
        operation_type: 'revoke',
        resource_ref: 'key:agk_x',
      },
      async () => ({ status: 200, body: { ok: true } }),
    );
    expect(out).toEqual({ status: 200, body: { ok: true } });
    const row = pg.rows.get('idk_1')!;
    expect(row.state).toBe('completed');
    expect(row.outcome_status).toBe(200);
  });

  it('replay with same key + payload returns cached completed outcome', async () => {
    const args = {
      idempotency_key: 'idk_replay',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke' as const,
      resource_ref: 'key:agk_x',
    };
    const op = async () => ({ status: 204, body: { revoked: true } });
    const first = await tierBIdempotent(asAdapter(pg), args, op);
    let opCalls = 0;
    const second = await tierBIdempotent(asAdapter(pg), args, async () => {
      opCalls++;
      return { status: 999, body: { mutated: true } };
    });
    expect(second).toEqual(first);
    expect(opCalls).toBe(0); // operation NOT re-run
  });

  it('replay with different payload returns 409 idempotency_key_payload_mismatch (RT-27)', async () => {
    const args1 = {
      idempotency_key: 'idk_x',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke' as const,
      resource_ref: 'key:agk_x',
    };
    await tierBIdempotent(asAdapter(pg), args1, async () => ({
      status: 200,
      body: {},
    }));
    await expect(
      tierBIdempotent(
        asAdapter(pg),
        { ...args1, request_hash: canonicalRequestHash({ a: 2 }) },
        async () => ({ status: 200, body: {} }),
      ),
    ).rejects.toMatchObject({ status: 409, code: 'idempotency_key_payload_mismatch' });
  });

  it('replay with different operation_type returns 409 idempotency_mismatch', async () => {
    const args = {
      idempotency_key: 'idk_op',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke' as const,
      resource_ref: 'key:agk_x',
    };
    await tierBIdempotent(asAdapter(pg), args, async () => ({ status: 200, body: {} }));
    await expect(
      tierBIdempotent(
        asAdapter(pg),
        { ...args, operation_type: 'rotate_emergency' },
        async () => ({ status: 200, body: {} }),
      ),
    ).rejects.toMatchObject({ status: 409, code: 'idempotency_mismatch' });
  });

  it('pending row replay returns 425 idempotency_in_flight', async () => {
    pg.rows.set('idk_inflight', {
      key: 'idk_inflight',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke',
      resource_ref: 'key:agk_x',
      outcome_status: null,
      outcome_body: null,
      state: 'pending',
      reconcile_attempts: 0,
      expires_at: new Date(Date.now() + 60_000),
      created_at: new Date(),
    });
    let caught: unknown;
    try {
      await tierBIdempotent(
        asAdapter(pg),
        {
          idempotency_key: 'idk_inflight',
          request_hash: canonicalRequestHash({ a: 1 }),
          operation_type: 'revoke',
          resource_ref: 'key:agk_x',
        },
        async () => ({ status: 200, body: {} }),
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AgentAuthError);
    const e = caught as AgentAuthError;
    expect(e.status).toBe(425);
    expect(e.code).toBe('idempotency_in_flight');
    expect(e.headers).toEqual({ 'Retry-After': '1' });
  });

  it('TierBTimeoutError marks row unknown and surfaces 503', async () => {
    let caught: unknown;
    try {
      await tierBIdempotent(
        asAdapter(pg),
        {
          idempotency_key: 'idk_to',
          request_hash: canonicalRequestHash({ a: 1 }),
          operation_type: 'revoke',
          resource_ref: 'key:agk_x',
        },
        async () => {
          throw new TierBTimeoutError();
        },
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ServiceUnavailableError);
    expect((caught as ServiceUnavailableError).code).toBe('idempotency_unknown_outcome');
    expect(pg.rows.get('idk_to')!.state).toBe('unknown');
  });

  it('business 4xx error inside operation marks row failed and re-throws', async () => {
    let caught: unknown;
    try {
      await tierBIdempotent(
        asAdapter(pg),
        {
          idempotency_key: 'idk_fail',
          request_hash: canonicalRequestHash({ a: 1 }),
          operation_type: 'revoke',
          resource_ref: 'key:agk_x',
        },
        async () => {
          throw new AgentAuthError(409, 'already_revoked');
        },
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AgentAuthError);
    expect((caught as AgentAuthError).status).toBe(409);
    const row = pg.rows.get('idk_fail')!;
    expect(row.state).toBe('failed');
    expect(row.outcome_status).toBe(409);
  });

  it('replay of a failed row returns the cached business error', async () => {
    const args = {
      idempotency_key: 'idk_fail2',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke' as const,
      resource_ref: 'key:agk_x',
    };
    let opCalls = 0;
    try {
      await tierBIdempotent(asAdapter(pg), args, async () => {
        opCalls++;
        throw new AgentAuthError(409, 'already_revoked');
      });
    } catch {
      /* swallow */
    }
    await expect(
      tierBIdempotent(asAdapter(pg), args, async () => {
        opCalls++;
        return { status: 200, body: {} };
      }),
    ).rejects.toMatchObject({
      status: 409,
      // SPEC §5.1.3 — replay must return the same response as the first
      // call. The wire-shape `code` must reflect the original error
      // (`already_revoked`), not a generic `invalid_request`.
      code: 'already_revoked',
      details: { replay: true },
    });
    expect(opCalls).toBe(1); // operation NOT re-run on the second call
  });

  it('replay of unknown state surfaces 503 idempotency_unknown_outcome', async () => {
    pg.rows.set('idk_unk', {
      key: 'idk_unk',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke',
      resource_ref: 'key:agk_x',
      outcome_status: null,
      outcome_body: null,
      state: 'unknown',
      reconcile_attempts: 0,
      expires_at: new Date(Date.now() + 60_000),
      created_at: new Date(),
    });
    await expect(
      tierBIdempotent(
        asAdapter(pg),
        {
          idempotency_key: 'idk_unk',
          request_hash: canonicalRequestHash({ a: 1 }),
          operation_type: 'revoke',
          resource_ref: 'key:agk_x',
        },
        async () => ({ status: 200, body: {} }),
      ),
    ).rejects.toMatchObject({ status: 503, code: 'idempotency_unknown_outcome' });
  });

  it('replay of manual_required surfaces 503 idempotency_manual_required', async () => {
    pg.rows.set('idk_mr', {
      key: 'idk_mr',
      request_hash: canonicalRequestHash({ a: 1 }),
      operation_type: 'revoke',
      resource_ref: 'key:agk_x',
      outcome_status: null,
      outcome_body: null,
      state: 'manual_required',
      reconcile_attempts: 5,
      expires_at: new Date(Date.now() + 60_000),
      created_at: new Date(),
    });
    await expect(
      tierBIdempotent(
        asAdapter(pg),
        {
          idempotency_key: 'idk_mr',
          request_hash: canonicalRequestHash({ a: 1 }),
          operation_type: 'revoke',
          resource_ref: 'key:agk_x',
        },
        async () => ({ status: 200, body: {} }),
      ),
    ).rejects.toMatchObject({ status: 503, code: 'idempotency_manual_required' });
  });
});
