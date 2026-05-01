import { describe, it, expect, beforeEach } from 'vitest';
import {
  reconcileUnknownIdempotency,
  type ResourceState,
} from '../../src/jobs/reconcile-idempotency.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface IdemRow {
  key: string;
  operation_type: string;
  resource_ref: string;
  state: 'pending' | 'unknown' | 'completed' | 'failed' | 'manual_required';
  reconcile_attempts: number;
  last_reconcile_at: Date | null;
  created_at: Date;
  outcome_status?: number;
  outcome_body?: unknown;
  manual_required_at?: Date;
}

class FakePg {
  rows: IdemRow[] = [];

  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    if (/SELECT key, operation_type, resource_ref, reconcile_attempts/.test(text)) {
      const cutoff = params[0] as Date;
      const stale = this.rows
        .filter(
          (r) =>
            (r.state === 'pending' || r.state === 'unknown') && r.created_at < cutoff,
        )
        .sort((a, b) => a.created_at.getTime() - b.created_at.getTime())
        .slice(0, 100);
      return {
        rows: stale.map((r) => ({
          key: r.key,
          operation_type: r.operation_type,
          resource_ref: r.resource_ref,
          reconcile_attempts: r.reconcile_attempts,
          last_reconcile_at: r.last_reconcile_at,
        })) as unknown as R[],
        rowCount: stale.length,
      };
    }
    if (/SET state = 'manual_required'/.test(text)) {
      const r = this.rows.find((x) => x.key === (params[0] as string));
      if (r && (r.state === 'pending' || r.state === 'unknown')) {
        r.state = 'manual_required';
        r.manual_required_at = new Date();
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/reconcile_attempts \+ 1/.test(text)) {
      const r = this.rows.find((x) => x.key === (params[0] as string));
      if (r) {
        r.reconcile_attempts++;
        r.last_reconcile_at = new Date();
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/SET state = 'completed'/.test(text)) {
      const r = this.rows.find((x) => x.key === (params[0] as string));
      if (r && (r.state === 'pending' || r.state === 'unknown')) {
        r.state = 'completed';
        r.outcome_status = params[1] as number;
        r.outcome_body = JSON.parse(params[2] as string);
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/SET state = 'failed'/.test(text)) {
      const r = this.rows.find((x) => x.key === (params[0] as string));
      // Mirror the SQL's WHERE clause so a pending-only-allowed
      // SET would be filtered like the SQL does.
      const whereStateClause = /WHERE key = \$1 AND state IN \('pending', 'unknown'\)/.test(text)
        ? (s: string) => s === 'pending' || s === 'unknown'
        : (s: string) => s === 'unknown';
      if (r && whereStateClause(r.state)) {
        r.state = 'failed';
        r.outcome_status = 500;
        r.outcome_body = JSON.parse(params[1] as string);
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    return { rows: [], rowCount: 0 };
  }

  async queryOne<R>(): Promise<R | null> {
    return null;
  }
}

function asAdapter(p: FakePg): PostgresAdapter {
  return p as unknown as PostgresAdapter;
}

describe('reconcileUnknownIdempotency (SPEC §5.1.2)', () => {
  let pg: FakePg;
  const now = new Date('2026-04-30T12:00:00Z');
  const stale_at = new Date(now.getTime() - 10 * 60 * 1000); // 10 min ago

  beforeEach(() => {
    pg = new FakePg();
  });

  it('promotes too-many-attempt rows to manual_required (pages oncall)', async () => {
    pg.rows.push({
      key: 'idk_a',
      operation_type: 'revoke',
      resource_ref: 'key:agk_x',
      state: 'unknown',
      reconcile_attempts: 5,
      last_reconcile_at: null,
      created_at: stale_at,
    });
    const paged: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        pageOncall: (label, meta) => paged.push({ label, meta }),
        checkResourceState: async () => ({ kind: 'indeterminate' as const }),
      },
      now,
    );
    expect(out.promoted_manual_required).toBe(1);
    expect(pg.rows[0]!.state).toBe('manual_required');
    expect(paged).toEqual([
      {
        label: 'idempotency_manual_required',
        meta: { key: 'idk_a', operation_type: 'revoke', resource_ref: 'key:agk_x' },
      },
    ]);
  });

  it('promotes committed resource state to completed', async () => {
    pg.rows.push({
      key: 'idk_b',
      operation_type: 'revoke',
      resource_ref: 'key:agk_y',
      state: 'unknown',
      reconcile_attempts: 0,
      last_reconcile_at: null,
      created_at: stale_at,
    });
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        checkResourceState: async (): Promise<ResourceState> => ({
          kind: 'committed',
          outcome_status: 204,
          outcome_body: { revoked: true },
        }),
      },
      now,
    );
    expect(out.promoted_completed).toBe(1);
    expect(pg.rows[0]!.state).toBe('completed');
    expect(pg.rows[0]!.outcome_status).toBe(204);
  });

  it('SPEC §5.1.2: stale pending + not_found also promotes to failed (not just unknown)', async () => {
    // Without this fix, a stale pending row whose resource is not_found
    // would stay pending until the 5-attempt cap-out (25 min), blocking
    // retries with 425 idempotency_in_flight the entire time.
    pg.rows.push({
      key: 'idk_pending_lost',
      operation_type: 'revoke',
      resource_ref: 'key:agk_lost',
      state: 'pending',
      reconcile_attempts: 0,
      last_reconcile_at: null,
      created_at: stale_at,
    });
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        checkResourceState: async () => ({ kind: 'not_found' as const }),
      },
      now,
    );
    expect(out.promoted_failed).toBe(1);
    expect(pg.rows[0]!.state).toBe('failed');
    expect(pg.rows[0]!.outcome_body).toEqual({ error: { code: 'commit_lost' } });
  });

  it('promotes not_found to failed when state is unknown', async () => {
    pg.rows.push({
      key: 'idk_c',
      operation_type: 'revoke',
      resource_ref: 'key:agk_z',
      state: 'unknown',
      reconcile_attempts: 0,
      last_reconcile_at: null,
      created_at: stale_at,
    });
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        checkResourceState: async () => ({ kind: 'not_found' as const }),
      },
      now,
    );
    expect(out.promoted_failed).toBe(1);
    expect(pg.rows[0]!.state).toBe('failed');
  });

  it('leaves indeterminate rows pending and bumps reconcile_attempts', async () => {
    pg.rows.push({
      key: 'idk_d',
      operation_type: 'revoke',
      resource_ref: 'key:agk_w',
      state: 'unknown',
      reconcile_attempts: 1,
      last_reconcile_at: null,
      created_at: stale_at,
    });
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        checkResourceState: async () => ({ kind: 'indeterminate' as const }),
      },
      now,
    );
    expect(out.inspected).toBe(1);
    expect(pg.rows[0]!.state).toBe('unknown');
    expect(pg.rows[0]!.reconcile_attempts).toBe(2);
  });

  it('does not touch fresh rows (younger than 5 minutes)', async () => {
    pg.rows.push({
      key: 'idk_fresh',
      operation_type: 'revoke',
      resource_ref: 'key:agk_x',
      state: 'unknown',
      reconcile_attempts: 0,
      last_reconcile_at: null,
      created_at: new Date(now.getTime() - 60_000), // 1 min ago
    });
    const out = await reconcileUnknownIdempotency(
      {
        postgres: asAdapter(pg),
        checkResourceState: async () => ({ kind: 'committed', outcome_status: 200, outcome_body: {} }),
      },
      now,
    );
    expect(out.inspected).toBe(0);
    expect(pg.rows[0]!.state).toBe('unknown');
  });
});
