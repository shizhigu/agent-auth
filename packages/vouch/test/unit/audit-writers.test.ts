import { describe, it, expect, beforeEach } from 'vitest';
import { writeAuditRow, pseudonymizeIp } from '../../src/audit/db-writer.js';
import {
  InMemoryWormPutter,
  writeAuditToWorm,
} from '../../src/audit/worm-writer.js';
import { flushAuditOutbox } from '../../src/jobs/outbox-flusher.js';
import { verifyAuditChain } from '../../src/jobs/audit-verifier.js';
import {
  ZERO_HASH,
  computeRowHash,
} from '../../src/crypto/audit-hash.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface AuditRow {
  id: string;
  ts: Date;
  event_type: string;
  account_id: string | null;
  key_id: string | null;
  identity_id: string | null;
  endpoint: string | null;
  status_class: number | null;
  meta: Record<string, unknown> | null;
  prev_hash: Buffer;
  row_hash: Buffer;
}
interface OutboxRow {
  id: string;
  event_id: string;
  payload: string;
  attempts: number;
  flushed_at: Date | null;
  created_at: Date;
  last_error: string | null;
}

class FakeDb {
  audit: AuditRow[] = [];
  outbox: OutboxRow[] = [];
  nextId = 1;
  nextOutboxId = 1;

  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    if (/INSERT INTO agent_audit_log/.test(text)) {
      const ts = (params[0] as Date | null) ?? new Date();
      const meta_str = params[11] as string | null;
      const meta = meta_str ? (JSON.parse(meta_str) as Record<string, unknown>) : null;
      const id = String(this.nextId++);
      const prev =
        this.audit.length > 0
          ? this.audit[this.audit.length - 1]!.row_hash
          : ZERO_HASH;
      const row_hash = computeRowHash(prev, {
        id: Number(id),
        ts,
        event_type: params[4] as string,
        account_id: (params[1] as string | null) ?? null,
        key_id: (params[2] as string | null) ?? null,
        endpoint: (params[5] as string | null) ?? null,
        status_class: (params[9] as number | null) ?? null,
        meta,
      });
      const row: AuditRow = {
        id,
        ts,
        event_type: params[4] as string,
        account_id: (params[1] as string | null) ?? null,
        key_id: (params[2] as string | null) ?? null,
        identity_id: (params[3] as string | null) ?? null,
        endpoint: (params[5] as string | null) ?? null,
        status_class: (params[9] as number | null) ?? null,
        meta,
        prev_hash: prev,
        row_hash,
      };
      this.audit.push(row);
      return {
        rows: [{ id: row.id, ts: row.ts, row_hash: row.row_hash, prev_hash: row.prev_hash }] as unknown as R[],
        rowCount: 1,
      };
    }
    if (/SELECT id::text AS id, event_id::text AS event_id, payload, attempts, created_at/.test(text)) {
      // Working SELECT: now also filters out attempts >= max_attempts so
      // stuck rows don't starve fresh ones (SPEC §6.4.2 invariant).
      const limit = params[0] as number;
      const max_attempts = params[1] as number;
      const rows = this.outbox
        .filter((o) => o.flushed_at === null && o.attempts < max_attempts)
        .sort((a, b) => a.created_at.getTime() - b.created_at.getTime())
        .slice(0, limit);
      return {
        rows: rows as unknown as R[],
        rowCount: rows.length,
      };
    }
    if (/SELECT id::text AS id, event_id::text AS event_id, attempts/.test(text)) {
      // Stuck SELECT.
      const max_attempts = params[0] as number;
      const rows = this.outbox
        .filter((o) => o.flushed_at === null && o.attempts >= max_attempts)
        .sort((a, b) => Number(a.id) - Number(b.id))
        .slice(0, 100);
      return {
        rows: rows as unknown as R[],
        rowCount: rows.length,
      };
    }
    if (/INSERT INTO agent_audit_outbox/.test(text)) {
      this.outbox.push({
        id: String(this.nextOutboxId++),
        event_id: params[0] as string,
        payload: params[1] as string,
        attempts: 0,
        flushed_at: null,
        created_at: new Date(),
        last_error: (params[2] as string | null) ?? null,
      });
      return { rows: [], rowCount: 1 };
    }
    if (/UPDATE agent_audit_outbox[\s\S]*flushed_at = now/.test(text)) {
      const id = params[0] as string;
      const r = this.outbox.find((o) => o.id === id);
      if (r) r.flushed_at = new Date();
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/UPDATE agent_audit_outbox[\s\S]*attempts = attempts \+ 1/.test(text)) {
      const id = params[0] as string;
      const r = this.outbox.find((o) => o.id === id);
      if (r) {
        r.attempts++;
        r.last_error = (params[1] as string | null) ?? null;
      }
      return { rows: [], rowCount: r ? 1 : 0 };
    }
    if (/SELECT id::text AS id, ts, event_type/.test(text)) {
      // verifyAuditChain reads today's rows.
      const since = params[0] as Date;
      const rows = this.audit.filter((r) => r.ts >= since);
      return {
        rows: rows.map((r) => ({
          id: r.id,
          ts: r.ts,
          event_type: r.event_type,
          account_id: r.account_id,
          key_id: r.key_id,
          endpoint: r.endpoint,
          status_class: r.status_class,
          meta: r.meta,
          prev_hash: r.prev_hash,
          row_hash: r.row_hash,
        })) as unknown as R[],
        rowCount: rows.length,
      };
    }
    return { rows: [], rowCount: 0 };
  }
  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    const out = await this.query<R>(text, params);
    return (out.rows[0] as R) ?? null;
  }
  async transaction<T>(fn: (c: FakeDb) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

function asAdapter(d: FakeDb): PostgresAdapter {
  return d as unknown as PostgresAdapter;
}

describe('writeAuditRow (SPEC §6.4.1)', () => {
  let db: FakeDb;
  beforeEach(() => {
    db = new FakeDb();
  });

  it('inserts a row, scrubs meta, returns id + ts + row_hash', async () => {
    const out = await writeAuditRow(
      {
        event_type: 'key_validated',
        account_id: 'acc-1',
        key_id: 'agk_x',
        endpoint: '/api/agent-auth/validate',
        status_class: 2,
        meta: {
          // The Authorization key value should be scrubbed.
          Authorization: 'Bearer agk_xxxxxxxx.' + 'a'.repeat(43),
          ok: true,
        },
      },
      { postgres: asAdapter(db) },
    );
    expect(out.id).toBe('1');
    expect(out.row_hash.length).toBe(32);
    const stored = db.audit[0]!;
    expect(stored.event_type).toBe('key_validated');
    expect(stored.meta).toMatchObject({ Authorization: '[REDACTED:KEY]' });
  });

  it('chains rows: prev_hash of row 2 equals row_hash of row 1', async () => {
    const a = await writeAuditRow(
      { event_type: 'a' },
      { postgres: asAdapter(db) },
    );
    const b = await writeAuditRow(
      { event_type: 'b' },
      { postgres: asAdapter(db) },
    );
    expect(b.prev_hash.equals(a.row_hash)).toBe(true);
  });
});

describe('pseudonymizeIp', () => {
  it('produces 32 bytes deterministically', () => {
    const sec = Buffer.alloc(32, 7);
    const a = pseudonymizeIp('1.2.3.4', sec);
    const b = pseudonymizeIp('1.2.3.4', sec);
    expect(a.length).toBe(32);
    expect(a.equals(b)).toBe(true);
    expect(a.equals(pseudonymizeIp('5.6.7.8', sec))).toBe(false);
  });
});

describe('writeAuditToWorm + outbox fallback (SPEC §6.4.2)', () => {
  let db: FakeDb;
  beforeEach(() => {
    db = new FakeDb();
  });

  it('happy path: PutObject succeeds, no outbox row', async () => {
    const putter = new InMemoryWormPutter();
    const out = await writeAuditToWorm(
      asAdapter(db),
      {
        bucket: 'b',
        kms_key_id: 'k',
        retention_years: 7,
        putter,
      },
      {
        id: '1',
        ts: new Date('2026-04-30T12:00:00Z'),
        event_type: 'e',
        row_hash: 'a'.repeat(64),
        prev_hash: 'b'.repeat(64),
      },
    );
    expect(out.status).toBe('ok');
    expect(putter.puts).toHaveLength(1);
    expect(putter.puts[0]!.ObjectLockMode).toBe('COMPLIANCE');
    expect(putter.puts[0]!.Key).toMatch(/^audit\/2026\/04\/30\/1\.json$/);
    expect(db.outbox).toHaveLength(0);
  });

  it('PutObject failure enqueues an outbox row', async () => {
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    const out = await writeAuditToWorm(
      asAdapter(db),
      { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
      {
        id: '2',
        ts: new Date('2026-04-30T12:00:00Z'),
        event_type: 'e',
        row_hash: 'a'.repeat(64),
        prev_hash: 'b'.repeat(64),
      },
    );
    expect(out.status).toBe('outboxed');
    expect(db.outbox).toHaveLength(1);
    expect(db.outbox[0]!.event_id).toBe('2');
    expect(db.outbox[0]!.flushed_at).toBeNull();
  });

  it('RT-28: tier=B PutObject failure throws audit_unavailable AND enqueues outbox row', async () => {
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    await expect(
      writeAuditToWorm(
        asAdapter(db),
        { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
        {
          id: '3',
          ts: new Date('2026-04-30T12:00:00Z'),
          event_type: 'tier_b_revoke',
          row_hash: 'a'.repeat(64),
          prev_hash: 'b'.repeat(64),
          tier: 'B',
        },
      ),
    ).rejects.toMatchObject({ status: 503, code: 'audit_unavailable' });
    // Even on throw, the outbox row is durable so retries can drain.
    expect(db.outbox).toHaveLength(1);
    expect(db.outbox[0]!.event_id).toBe('3');
  });

  it('tier=A (default) failure does NOT throw: best-effort returns outboxed', async () => {
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    const out = await writeAuditToWorm(
      asAdapter(db),
      { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
      {
        id: '4',
        ts: new Date('2026-04-30T12:00:00Z'),
        event_type: 'tier_a_validate',
        row_hash: 'a'.repeat(64),
        prev_hash: 'b'.repeat(64),
      },
    );
    expect(out.status).toBe('outboxed');
  });
});

describe('flushAuditOutbox (SPEC §6.4.2)', () => {
  it('drains pending rows on PutObject success', async () => {
    const db = new FakeDb();
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    await writeAuditToWorm(
      asAdapter(db),
      { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
      {
        id: '7',
        ts: new Date('2026-04-30T12:00:00Z'),
        event_type: 'e',
        row_hash: 'a'.repeat(64),
        prev_hash: 'b'.repeat(64),
      },
    );
    expect(db.outbox).toHaveLength(1);

    const result = await flushAuditOutbox({
      postgres: asAdapter(db),
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
    });
    expect(result.flushed).toBe(1);
    expect(db.outbox[0]!.flushed_at).not.toBeNull();
  });

  it('keeps stuck rows after max_attempts and pages oncall', async () => {
    const db = new FakeDb();
    db.outbox.push({
      id: '1',
      event_id: '99',
      payload: '{"ts":"2026-04-30T12:00:00Z"}',
      attempts: 10,
      flushed_at: null,
      created_at: new Date(),
      last_error: null,
    });
    const alerts: Array<{ label: string }> = [];
    const result = await flushAuditOutbox({
      postgres: asAdapter(db),
      putter: new InMemoryWormPutter(),
      cfg: { kms_key_id: 'k', retention_years: 7 },
      max_attempts: 10,
      onAlert: (label) => alerts.push({ label }),
    });
    expect(result.stuck).toBe(1);
    expect(alerts).toContainEqual({ label: 'audit_outbox_stuck' });
  });
});

describe('verifyAuditChain (SPEC §6.4.1)', () => {
  it('returns first_break_index=-1 for an intact chain', async () => {
    const db = new FakeDb();
    await writeAuditRow({ event_type: 'a' }, { postgres: asAdapter(db) });
    await writeAuditRow({ event_type: 'b' }, { postgres: asAdapter(db) });
    const out = await verifyAuditChain({ postgres: asAdapter(db) });
    expect(out.first_break_index).toBe(-1);
    expect(out.inspected).toBe(2);
  });

  it('detects a tampered row and pages onAlert', async () => {
    const db = new FakeDb();
    await writeAuditRow({ event_type: 'a' }, { postgres: asAdapter(db) });
    await writeAuditRow({ event_type: 'b' }, { postgres: asAdapter(db) });
    // Tamper: flip a byte in row 1's row_hash so row 2's prev_hash no longer matches.
    db.audit[0]!.row_hash = Buffer.from(db.audit[0]!.row_hash).fill(0xff);
    const alerts: Array<Record<string, unknown>> = [];
    const out = await verifyAuditChain({
      postgres: asAdapter(db),
      onAlert: (label, meta) => alerts.push({ label, ...meta }),
    });
    expect(out.first_break_index).toBeGreaterThanOrEqual(0);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.label).toBe('audit_hash_chain_break');
  });
});
