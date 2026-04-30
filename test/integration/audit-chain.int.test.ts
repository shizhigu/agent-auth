/**
 * Integration: audit hash chain against real Postgres trigger. SPEC §6.4.1
 * + §3.8.
 *
 * Writes audit rows via writeAuditRow (Postgres trigger computes prev_hash
 * and row_hash). Verifies the chain end-to-end via verifyAuditChain. Then
 * tampers with one row's row_hash via the admin role and asserts the
 * verifier detects the break + emits onAlert.
 *
 * Covers RT-12 (audit log tamper) and RT-39 (audit omission detection).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { writeAuditRow, writeAuditRowOnClient } from '../../src/audit/db-writer.js';
import { verifyAuditChain } from '../../src/jobs/audit-verifier.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import { ZERO_HASH } from '../../src/crypto/audit-hash.js';

describe('integration: audit hash chain (SPEC §6.4.1 / RT-12)', () => {
  let fix: IntegrationFixture;
  /** Admin-role adapter so we can simulate a tamper UPDATE that the
   *  app-role policy normally REVOKEs. */
  let adminPg: PostgresAdapter;

  beforeAll(async () => {
    fix = await provisionFixture();
    // Build a separate adapter that runs as the admin role. The boot user
    // already inherits agent_auth_admin from setup.ts.
    adminPg = new PostgresAdapter({
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
    await adminPg?.close().catch(() => undefined);
    await fix.cleanup();
  }, 120_000);

  it('verifyAuditChain returns -1 for an intact chain', async () => {
    // Write 3 rows.
    const a = await writeAuditRow(
      { event_type: 'integration_a', status_class: 2 },
      { postgres: fix.postgres },
    );
    const b = await writeAuditRow(
      { event_type: 'integration_b', status_class: 2 },
      { postgres: fix.postgres },
    );
    const c = await writeAuditRow(
      { event_type: 'integration_c', status_class: 2 },
      { postgres: fix.postgres },
    );
    // Chain links: prev_hash(b) == row_hash(a); prev_hash(c) == row_hash(b).
    expect(b.prev_hash.equals(a.row_hash)).toBe(true);
    expect(c.prev_hash.equals(b.row_hash)).toBe(true);

    const out = await verifyAuditChain({ postgres: adminPg });
    expect(out.first_break_index).toBe(-1);
    expect(out.inspected).toBeGreaterThanOrEqual(3);
  });

  it('cross-day independence: a chain spanning two UTC days verifies as two independent chains', async () => {
    // Insert two rows on day D1 with explicit ts; then two rows on day D2.
    // Without per-day scoping, the verifier would see prev_hash(D2[0]) ==
    // ZERO_HASH (per the §3.8 trigger) but the previous row in id order
    // would be D1[1] with row_hash != ZERO_HASH — a false-positive break.
    // With per-day scoping each chain is checked against ZERO_HASH seed.
    const D1 = new Date('2026-09-10T12:00:00Z');
    const D2 = new Date('2026-09-11T01:00:00Z');
    await writeAuditRow(
      { event_type: 'cross_day_a', status_class: 2, ts: D1 },
      { postgres: fix.postgres },
    );
    await writeAuditRow(
      { event_type: 'cross_day_b', status_class: 2, ts: D1 },
      { postgres: fix.postgres },
    );
    await writeAuditRow(
      { event_type: 'cross_day_c', status_class: 2, ts: D2 },
      { postgres: fix.postgres },
    );
    await writeAuditRow(
      { event_type: 'cross_day_d', status_class: 2, ts: D2 },
      { postgres: fix.postgres },
    );

    // Verify D1 in isolation — intact.
    const out_d1 = await verifyAuditChain({
      postgres: adminPg,
      target_day: D1,
    });
    expect(out_d1.first_break_index).toBe(-1);
    expect(out_d1.inspected).toBeGreaterThanOrEqual(2);

    // Verify D2 in isolation — intact (own chain seeded with ZERO_HASH).
    const out_d2 = await verifyAuditChain({
      postgres: adminPg,
      target_day: D2,
    });
    expect(out_d2.first_break_index).toBe(-1);
    expect(out_d2.inspected).toBeGreaterThanOrEqual(2);
  });

  it('detects tampering — UPDATEing a row_hash via admin role surfaces audit_hash_chain_break', async () => {
    // The app role has INSERT-only on agent_audit_log; tampering must use
    // the admin role (which itself logs the override per §3.13 / 0004).
    // We're modeling RB-6 tamper detection — operator inspects, finds
    // exactly the break the verifier flagged.
    const target = await adminPg.queryOne<{ id: string }>(
      `SELECT id::text AS id FROM agent_audit_log
        WHERE event_type = 'integration_a' ORDER BY id ASC LIMIT 1`,
    );
    expect(target).toBeDefined();
    // Flip a byte in the target row's row_hash. This breaks the link to
    // any subsequent row whose prev_hash was derived from the original.
    const tampered = Buffer.alloc(32, 0xff);
    await adminPg.query(
      `UPDATE agent_audit_log SET row_hash = $2 WHERE id = $1::bigint`,
      [target!.id, tampered],
    );

    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const out = await verifyAuditChain({
      postgres: fix.postgres,
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(out.first_break_index).toBeGreaterThanOrEqual(0);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.label).toBe('audit_hash_chain_break');
    expect(alerts[0]!.meta).toMatchObject({ at_id: expect.any(String) });
  });

  it('chain seed aligns to UTC even when session TIMEZONE is non-UTC (SPEC §3.8 / RT-12)', async () => {
    // 23:50Z and 00:30Z+1 — same UTC-day boundary, but in LA (UTC-8 in
    // December) both fall within the same local day. Without the 0005
    // fix the trigger uses session-local date_trunc and chains them
    // together, producing a non-ZERO prev_hash on the first row of the
    // new UTC day. The UTC-scoped verifier seeds with ZERO_HASH and
    // would surface a false break.
    const D1 = new Date('2027-01-15T23:50:00Z');
    const D2 = new Date('2027-01-16T00:30:00Z');
    await fix.postgres.withClient(async (client) => {
      await client.query("SET TIME ZONE 'America/Los_Angeles'");
      await writeAuditRowOnClient(client, {
        event_type: 'utc_align_d1',
        status_class: 2,
        ts: D1,
      });
      await writeAuditRowOnClient(client, {
        event_type: 'utc_align_d2',
        status_class: 2,
        ts: D2,
      });
    });

    // Confirm prev_hash of the first D2 row really is ZERO_HASH —
    // i.e. the trigger correctly treated D2 as a fresh UTC day.
    const d2_first = await adminPg.queryOne<{ prev_hash: Buffer }>(
      `SELECT prev_hash FROM agent_audit_log
        WHERE event_type = 'utc_align_d2'
        ORDER BY id ASC LIMIT 1`,
    );
    expect(d2_first).toBeDefined();
    const got = Buffer.isBuffer(d2_first!.prev_hash)
      ? d2_first!.prev_hash
      : Buffer.from(d2_first!.prev_hash);
    expect(got.equals(ZERO_HASH)).toBe(true);

    // And the verifier sees an intact chain on the D2 UTC day.
    const out = await verifyAuditChain({
      postgres: adminPg,
      target_day: D2,
    });
    expect(out.first_break_index).toBe(-1);
  });
});
