/**
 * Integration: daily audit-log partition manager. SPEC §3.8 + §13.1.2.
 *
 *   - manageAuditPartitions creates `lookahead_days` daily partitions
 *     attached to agent_audit_log; on rerun the same day, partitions
 *     are skipped (idempotent).
 *   - A row inserted with `ts` falling inside a created partition lands
 *     in that partition (not in agent_audit_log_default).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { manageAuditPartitions } from '../../src/jobs/audit-partition-manager.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

describe('integration: audit partition manager (SPEC §3.8 / §13.1.2)', () => {
  let fix: IntegrationFixture;
  let admin: PostgresAdapter;
  /** Anchor 'now' to a stable date so rerun assertions are deterministic. */
  const NOW = new Date('2027-06-15T12:00:00Z');

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
      // Partition creation needs CREATE on the schema; per SPEC §3.16 only
      // the migrator role has it (admin is for runbooks; app is read+write
      // on existing tables only).
      role: 'agent_auth_migrator',
    });
  }, 240_000);

  afterAll(async () => {
    await admin?.close().catch(() => undefined);
    await fix.cleanup();
  }, 120_000);

  it('creates lookahead_days daily partitions; second run skips all of them', async () => {
    const out1 = await manageAuditPartitions({
      postgres: admin,
      lookahead_days: 3,
      now: () => NOW,
    });
    expect(out1.created).toHaveLength(3);
    expect(out1.skipped).toHaveLength(0);
    expect(out1.created).toEqual([
      'agent_audit_log_2027_06_15',
      'agent_audit_log_2027_06_16',
      'agent_audit_log_2027_06_17',
    ]);

    // pg_class confirms the partitions exist as relkind='r' (real tables).
    const rels = await admin.query<{ relname: string }>(
      `SELECT relname FROM pg_class
        WHERE relname = ANY($1::text[])
        ORDER BY relname`,
      [out1.created as unknown as string[]],
    );
    expect(rels.rows.map((r) => r.relname)).toEqual([
      'agent_audit_log_2027_06_15',
      'agent_audit_log_2027_06_16',
      'agent_audit_log_2027_06_17',
    ]);

    const out2 = await manageAuditPartitions({
      postgres: admin,
      lookahead_days: 3,
      now: () => NOW,
    });
    expect(out2.created).toHaveLength(0);
    expect(out2.skipped).toHaveLength(3);
  });

  it('row whose ts falls in a created partition lands in that partition (not default)', async () => {
    // Use NOW + 1 day so we land in agent_audit_log_2027_06_16 (created above).
    const ts = new Date('2027-06-16T10:00:00Z');
    const inserted = await admin.queryOne<{ id: string; tableoid: string }>(
      `INSERT INTO agent_audit_log
         (ts, event_type, status_class)
       VALUES ($1, 'partition_routing_test', 2)
       RETURNING id::text AS id, tableoid::regclass::text AS tableoid`,
      [ts],
    );
    expect(inserted).not.toBeNull();
    expect(inserted!.tableoid).toBe('agent_audit_log_2027_06_16');
  });

  it('rejects out-of-range lookahead_days', async () => {
    await expect(
      manageAuditPartitions({ postgres: admin, lookahead_days: 0, now: () => NOW }),
    ).rejects.toThrow('lookahead_days');
    await expect(
      manageAuditPartitions({ postgres: admin, lookahead_days: 91, now: () => NOW }),
    ).rejects.toThrow('lookahead_days');
  });
});
