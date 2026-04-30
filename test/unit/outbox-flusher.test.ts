/**
 * Unit: outbox flusher (SPEC §6.4.2).
 *
 * Two assertions about queue semantics that aren't covered by the
 * integration test (which only exercises a single stuck row):
 *
 *   1. stuck rows (attempts >= max_attempts) MUST NOT consume LIMIT
 *      slots — otherwise once `batch_size` stuck rows pile up, the
 *      flusher never advances past them and new outbox writes go
 *      unflushed indefinitely.
 *   2. stuck rows still surface 'audit_outbox_stuck' alerts so SREs
 *      see the backlog even when the working SELECT skips them.
 */
import { describe, it, expect, vi } from 'vitest';
import { flushAuditOutbox } from '../../src/jobs/outbox-flusher.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { WormPutter, S3WormPut } from '../../src/audit/worm-writer.js';

interface FakeRow {
  id: string;
  event_id: string;
  payload: unknown;
  attempts: number;
  created_at: Date;
  flushed_at: Date | null;
  last_error: string | null;
}

class FakePg {
  rows: FakeRow[] = [];
  readonly log: Array<{ text: string; params?: ReadonlyArray<unknown> }> = [];

  async query<R>(text: string, params?: ReadonlyArray<unknown>) {
    this.log.push(params !== undefined ? { text, params } : { text });
    if (text.includes('SELECT id::text AS id') && text.includes('attempts <')) {
      // Working SELECT — fix form, filters out stuck.
      const max_attempts = Number(params![1]);
      const limit = Number(params![0]);
      const out = this.rows
        .filter((r) => r.flushed_at === null && r.attempts < max_attempts)
        .sort((a, b) => a.created_at.getTime() - b.created_at.getTime())
        .slice(0, limit);
      return { rows: out as unknown as R[], rowCount: out.length };
    }
    if (text.includes('SELECT id::text AS id') && text.includes('attempts >=')) {
      // Stuck SELECT — fix form.
      const max_attempts = Number(params![0]);
      const out = this.rows
        .filter((r) => r.flushed_at === null && r.attempts >= max_attempts)
        .sort((a, b) => Number(a.id) - Number(b.id));
      return { rows: out as unknown as R[], rowCount: out.length };
    }
    if (text.includes('SET flushed_at = now()')) {
      const id = String(params![0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) r.flushed_at = new Date();
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    if (text.includes('SET attempts = attempts + 1')) {
      const id = String(params![0]);
      const r = this.rows.find((x) => x.id === id);
      if (r) r.attempts++;
      return { rows: [] as unknown as R[], rowCount: r ? 1 : 0 };
    }
    return { rows: [] as unknown as R[], rowCount: 0 };
  }
}

class HealthyPutter implements WormPutter {
  readonly puts: S3WormPut[] = [];
  async putObject(input: S3WormPut): Promise<void> {
    this.puts.push(input);
  }
}

describe('flushAuditOutbox (SPEC §6.4.2)', () => {
  it('does NOT let stuck rows starve the working set — fresh rows still flush even when batch_size is filled by stuck rows under the older form', async () => {
    const pg = new FakePg();
    // 3 stuck rows (oldest), then 1 fresh row.
    pg.rows = [
      { id: '1', event_id: '101', payload: { ts: '2026-04-29T00:00:00Z' }, attempts: 10, created_at: new Date('2026-04-29T00:00:00Z'), flushed_at: null, last_error: null },
      { id: '2', event_id: '102', payload: { ts: '2026-04-29T01:00:00Z' }, attempts: 10, created_at: new Date('2026-04-29T01:00:00Z'), flushed_at: null, last_error: null },
      { id: '3', event_id: '103', payload: { ts: '2026-04-29T02:00:00Z' }, attempts: 10, created_at: new Date('2026-04-29T02:00:00Z'), flushed_at: null, last_error: null },
      { id: '4', event_id: '104', payload: { ts: '2026-04-30T00:00:00Z' }, attempts: 0, created_at: new Date('2026-04-30T00:00:00Z'), flushed_at: null, last_error: null },
    ];
    const putter = new HealthyPutter();

    const out = await flushAuditOutbox({
      postgres: pg as unknown as PostgresAdapter,
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
      batch_size: 3,
      max_attempts: 10,
    });

    // Fresh row was reachable despite 3 stuck rows older than it.
    expect(out.flushed).toBe(1);
    // Stuck rows still surfaced.
    expect(out.stuck).toBe(3);
    // The fresh row's flushed_at is set.
    expect(pg.rows.find((r) => r.id === '4')!.flushed_at).not.toBeNull();
    // Stuck rows untouched (no flush, no attempts++).
    expect(pg.rows.find((r) => r.id === '1')!.attempts).toBe(10);
  });

  it('emits onAlert for each stuck row even when the working SELECT skips them', async () => {
    const pg = new FakePg();
    pg.rows = [
      { id: '1', event_id: '101', payload: { ts: '2026-04-29T00:00:00Z' }, attempts: 12, created_at: new Date('2026-04-29T00:00:00Z'), flushed_at: null, last_error: null },
      { id: '2', event_id: '102', payload: { ts: '2026-04-29T01:00:00Z' }, attempts: 11, created_at: new Date('2026-04-29T01:00:00Z'), flushed_at: null, last_error: null },
    ];
    const putter = new HealthyPutter();
    const onAlert = vi.fn();

    const out = await flushAuditOutbox({
      postgres: pg as unknown as PostgresAdapter,
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
      max_attempts: 10,
      onAlert,
    });

    expect(out.stuck).toBe(2);
    const labels = onAlert.mock.calls.map((c) => c[0]);
    expect(labels.filter((l) => l === 'audit_outbox_stuck')).toHaveLength(2);
  });

  it('flushed_at correctly bumps and stuck count is independent of batch_size', async () => {
    const pg = new FakePg();
    pg.rows = [
      { id: '1', event_id: '101', payload: { ts: '2026-04-30T00:00:00Z' }, attempts: 0, created_at: new Date('2026-04-30T00:00:00Z'), flushed_at: null, last_error: null },
      { id: '2', event_id: '102', payload: { ts: '2026-04-30T01:00:00Z' }, attempts: 12, created_at: new Date('2026-04-30T01:00:00Z'), flushed_at: null, last_error: null },
    ];
    const putter = new HealthyPutter();
    const out = await flushAuditOutbox({
      postgres: pg as unknown as PostgresAdapter,
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
      batch_size: 1,
      max_attempts: 10,
    });
    expect(out.flushed).toBe(1);
    expect(out.stuck).toBe(1);
    expect(pg.rows.find((r) => r.id === '1')!.flushed_at).not.toBeNull();
  });
});
