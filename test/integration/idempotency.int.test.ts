/**
 * Integration: idempotency state machine against real Postgres triggers.
 * SPEC §5.1 + §3.13 + RT-27.
 *
 * Postgres-side guarantees:
 *   - 0004 trigger `enforce_idempotency_transitions` rejects pending →
 *     manual_required and any transition out of a terminal state.
 *   - 0004 trigger `enforce_terminal_row_immutable` refuses any change to
 *     request_hash / outcome_status / outcome_body once the row is terminal.
 *
 * tierBIdempotent guarantees (against real DB):
 *   - phase 1 inserts pending row.
 *   - phase 2 commits and updates pending → completed in the SAME Tier B
 *     transaction.
 *   - replay with same key + payload returns cached completed response.
 *   - replay with different payload (RT-27) returns 409
 *     idempotency_key_payload_mismatch.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  provisionFixture,
  type IntegrationFixture,
} from './setup.js';
import {
  tierBIdempotent,
  canonicalRequestHash,
} from '../../src/reliability/idempotency.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import { AgentAuthError } from '../../src/errors.js';

describe('integration: idempotency (SPEC §5.1 / §3.13 / RT-27)', () => {
  let fix: IntegrationFixture;
  let admin: PostgresAdapter;

  beforeAll(async () => {
    fix = await provisionFixture();
    admin = new PostgresAdapter({
      pool: {
        host: fix.pg_container.getHost(),
        port: fix.pg_container.getPort(),
        database: fix.pg_container.getDatabase(),
        user: fix.pg_container.getUsername(),
        password: fix.pg_container.getPassword(),
      },
      role: 'agent_auth_admin',
    });
  }, 120_000);

  afterAll(async () => {
    await admin?.close().catch(() => undefined);
    await fix.cleanup();
  }, 120_000);

  it('phase 1+2: pending row created, then transitioned to completed atomically', async () => {
    const idem_key = `int_idem_${Date.now()}`;
    const result = await tierBIdempotent<{ ok: boolean }>(
      fix.postgres,
      {
        idempotency_key: idem_key,
        request_hash: canonicalRequestHash({ op: 'integration_op', n: 1 }),
        operation_type: 'revoke',
        resource_ref: 'integration:test:1',
      },
      async () => ({ status: 200, body: { ok: true } }),
    );
    expect(result).toEqual({ status: 200, body: { ok: true } });
    const row = await admin.queryOne<{ state: string; outcome_status: number }>(
      `SELECT state, outcome_status FROM agent_idempotency WHERE key = $1`,
      [idem_key],
    );
    expect(row?.state).toBe('completed');
    expect(row?.outcome_status).toBe(200);
  });

  it('replay with same key + payload returns cached response without re-running operation', async () => {
    const idem_key = `int_idem_replay_${Date.now()}`;
    const args = {
      idempotency_key: idem_key,
      request_hash: canonicalRequestHash({ op: 'integration_op', n: 1 }),
      operation_type: 'revoke' as const,
      resource_ref: 'integration:replay:1',
    };
    let calls = 0;
    const op = async () => {
      calls++;
      return { status: 204, body: { revoked: true } };
    };
    const a = await tierBIdempotent(fix.postgres, args, op);
    const b = await tierBIdempotent(fix.postgres, args, op);
    expect(a).toEqual(b);
    expect(calls).toBe(1); // operation NOT re-run on second call
  });

  it('RT-27: replay with mismatched payload returns 409 idempotency_key_payload_mismatch', async () => {
    const idem_key = `int_idem_mm_${Date.now()}`;
    const base = {
      idempotency_key: idem_key,
      operation_type: 'revoke' as const,
      resource_ref: 'integration:mm:1',
    };
    await tierBIdempotent(
      fix.postgres,
      { ...base, request_hash: canonicalRequestHash({ a: 1 }) },
      async () => ({ status: 200, body: {} }),
    );
    let caught: unknown;
    try {
      await tierBIdempotent(
        fix.postgres,
        { ...base, request_hash: canonicalRequestHash({ a: 2 }) },
        async () => ({ status: 200, body: {} }),
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AgentAuthError);
    const e = caught as AgentAuthError;
    expect(e.status).toBe(409);
    expect(e.code).toBe('idempotency_key_payload_mismatch');
  });

  it('§3.13 trigger: pending → manual_required REFUSED for app role; admin override emits audit event', async () => {
    const idem_key = `int_idem_trig_${Date.now()}`;
    // Plant a pending row directly via admin (app role can INSERT but the
    // canonical lifecycle goes through tierBIdempotent).
    await admin.query(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, expires_at)
         VALUES ($1, $2, 'revoke', 'integration:trig:1', 'pending',
                 now() + interval '1 hour')`,
      [idem_key, canonicalRequestHash({ x: 1 })],
    );
    // App role: rejected with check_violation.
    let appCaught: unknown;
    try {
      await fix.postgres.query(
        `UPDATE agent_idempotency SET state = 'manual_required' WHERE key = $1`,
        [idem_key],
      );
    } catch (err) {
      appCaught = err;
    }
    expect(appCaught).toBeDefined();
    expect((appCaught as { code?: string }).code).toBe('23514');

    // Admin role: override allowed AND emits an idempotency_admin_override
    // audit event in the same transaction.
    const auditBefore = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_log
        WHERE event_type = 'idempotency_admin_override'`,
    );
    await admin.query(
      `UPDATE agent_idempotency SET state = 'manual_required' WHERE key = $1`,
      [idem_key],
    );
    const auditAfter = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_log
        WHERE event_type = 'idempotency_admin_override'`,
    );
    expect(Number(auditAfter?.count ?? 0)).toBeGreaterThan(
      Number(auditBefore?.count ?? 0),
    );
  });

  it('§3.13 trigger: terminal row immutable (request_hash cannot change after completed)', async () => {
    const idem_key = `int_idem_immutable_${Date.now()}`;
    // Plant a completed row via the admin role + transition.
    await admin.query(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, outcome_status,
          outcome_body, expires_at)
         VALUES ($1, $2, 'revoke', 'integration:immut:1', 'completed', 200,
                 '{"ok":true}'::jsonb, now() + interval '1 hour')`,
      [idem_key, canonicalRequestHash({ x: 1 })],
    );
    let caught: unknown;
    try {
      await admin.query(
        `UPDATE agent_idempotency SET request_hash = $2 WHERE key = $1`,
        [idem_key, canonicalRequestHash({ x: 2 })],
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    const e = caught as { code?: string };
    expect(e.code).toBe('23514');
  });
});
