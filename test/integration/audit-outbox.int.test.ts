/**
 * Integration: audit outbox flusher against real Postgres + InMemoryWormPutter.
 * SPEC §6.4.2 / §6.2.4 RT-39.
 *
 * Verifies the outbox lifecycle:
 *   - writeAuditToWorm with a failing putter enqueues an outbox row.
 *   - flushAuditOutbox successfully drains the row on retry.
 *   - flushed_at is set; row_count of pending outbox drops.
 *   - Rows past max_attempts surface 'audit_outbox_stuck' alert.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import {
  InMemoryWormPutter,
  writeAuditToWorm,
} from '../../src/audit/worm-writer.js';
import { writeAuditRow } from '../../src/audit/db-writer.js';
import { flushAuditOutbox } from '../../src/jobs/outbox-flusher.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import { ServiceUnavailableError } from '../../src/errors.js';

describe('integration: audit outbox flusher (SPEC §6.4.2 / RT-39)', () => {
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

  it('failed PutObject → outbox row → flusher drains it on next pass', async () => {
    const written = await writeAuditRow(
      { event_type: 'integration_outbox', status_class: 2 },
      { postgres: fix.postgres },
    );
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;

    const result = await writeAuditToWorm(
      fix.postgres,
      { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
      {
        id: written.id,
        ts: written.ts,
        event_type: 'integration_outbox',
        row_hash: written.row_hash.toString('hex'),
        prev_hash: written.prev_hash.toString('hex'),
      },
    );
    expect(result.status).toBe('outboxed');

    const pending = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_outbox WHERE flushed_at IS NULL`,
    );
    expect(Number(pending?.count ?? '0')).toBeGreaterThanOrEqual(1);

    // Putter healthy on next call; flush should drain the queue.
    const drain = await flushAuditOutbox({
      postgres: admin,
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
    });
    expect(drain.flushed).toBeGreaterThanOrEqual(1);
    expect(drain.failed).toBe(0);
    expect(drain.stuck).toBe(0);

    const flushed = await admin.queryOne<{ flushed_at: Date | null }>(
      `SELECT flushed_at FROM agent_audit_outbox
        WHERE event_id = $1::bigint`,
      [written.id],
    );
    expect(flushed?.flushed_at).not.toBeNull();
  });

  it('RT-28: tier B event with failing WORM put → enqueues outbox AND throws 503 audit_unavailable', async () => {
    const written = await writeAuditRow(
      { event_type: 'tier_b_revoke_marker', status_class: 2 },
      { postgres: fix.postgres },
    );
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    const beforeCount = await admin.queryOne<{ c: string }>(
      `SELECT count(*)::text AS c FROM agent_audit_outbox
        WHERE event_id = $1::bigint`,
      [written.id],
    );

    // tier='B' triggers fail-closed: caller surfaces 503 to the client
    // even though the outbox row is durable for retry. RT-28 invariant —
    // an attacker who suppresses S3 cannot get a free pass to revoke.
    await expect(
      writeAuditToWorm(
        fix.postgres,
        { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
        {
          id: written.id,
          ts: written.ts,
          event_type: 'tier_b_revoke_marker',
          row_hash: written.row_hash.toString('hex'),
          prev_hash: written.prev_hash.toString('hex'),
          tier: 'B',
        },
      ),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);

    // Outbox row was still inserted — the operator can retry on next pass.
    const afterCount = await admin.queryOne<{ c: string }>(
      `SELECT count(*)::text AS c FROM agent_audit_outbox
        WHERE event_id = $1::bigint`,
      [written.id],
    );
    expect(Number(afterCount?.c ?? '0')).toBe(Number(beforeCount?.c ?? '0') + 1);
  });

  it('Tier A event with failing WORM put → outboxed (no throw); RT-28 fail-closed is Tier-B-only', async () => {
    const written = await writeAuditRow(
      { event_type: 'tier_a_validate_marker', status_class: 2 },
      { postgres: fix.postgres },
    );
    const putter = new InMemoryWormPutter();
    putter.shouldFailNext = 1;
    const result = await writeAuditToWorm(
      fix.postgres,
      { bucket: 'b', kms_key_id: 'k', retention_years: 7, putter },
      {
        id: written.id,
        ts: written.ts,
        event_type: 'tier_a_validate_marker',
        row_hash: written.row_hash.toString('hex'),
        prev_hash: written.prev_hash.toString('hex'),
        // tier omitted → defaults to 'A' (best-effort)
      },
    );
    expect(result.status).toBe('outboxed');
  });

  it('row past max_attempts is paged as audit_outbox_stuck', async () => {
    // Plant a stuck row directly: attempts=10 (default max_attempts).
    await admin.query(
      `INSERT INTO agent_audit_outbox (event_id, payload, attempts, last_error)
       VALUES (1, '{"ts":"2026-04-30T00:00:00Z"}'::jsonb, 10, 'simulated')`,
    );
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const putter = new InMemoryWormPutter();
    const result = await flushAuditOutbox({
      postgres: admin,
      putter,
      cfg: { kms_key_id: 'k', retention_years: 7 },
      max_attempts: 10,
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(result.stuck).toBeGreaterThanOrEqual(1);
    expect(alerts.some((a) => a.label === 'audit_outbox_stuck')).toBe(true);
  });
});
