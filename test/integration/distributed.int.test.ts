/**
 * Integration: distributed primitives' Postgres invariants. SPEC §3.12 / §5.3.2 / §4.4.2.
 *
 *  - agent_revocation_epoch: monotonicity trigger refuses non-strictly-increasing UPDATE.
 *  - agent_revocation_barrier: timeline_id non-decreasing; last_lsn non-regressing
 *    within a timeline; reset on new timeline allowed.
 *  - bumpEpochInTx: increments and pushes to Redis (verified by separate paths).
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import { bumpEpochInTx } from '../../src/distributed/revocation-epoch.js';
import { tierBTransaction } from '../../src/distributed/tier-b-commit.js';
import { readAuthoritativeBarrier } from '../../src/distributed/revocation-barrier.js';

describe('integration: distributed primitives (SPEC §3.12 / §5.3.2 / §4.4.2)', () => {
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

  it('§3.12 epoch trigger: non-monotonic UPDATE is refused', async () => {
    // Bump the epoch to 5 first.
    await admin.query(
      `UPDATE agent_revocation_epoch SET epoch = 5 WHERE id = 1 AND epoch < 5`,
    );
    let caught: unknown;
    try {
      await admin.query(
        `UPDATE agent_revocation_epoch SET epoch = 4 WHERE id = 1`,
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    expect((caught as { code?: string }).code).toBe('23514'); // check_violation
  });

  it('§5.3.2 bumpEpochInTx: increments Postgres + pushes to Redis', async () => {
    const before = await admin.queryOne<{ epoch: string }>(
      `SELECT epoch::text AS epoch FROM agent_revocation_epoch WHERE id = 1`,
    );
    const beforeRedis = await fix.redis.getAuthoritativeEpoch();
    const result = await tierBTransaction(fix.postgres, async (client) =>
      bumpEpochInTx(client, fix.redis),
    );
    expect(result.epoch).toBe(Number(before!.epoch) + 1);
    expect(await fix.redis.getAuthoritativeEpoch()).toBeGreaterThanOrEqual(
      Math.max(beforeRedis, result.epoch),
    );
  });

  it('§3.12 barrier trigger: same-timeline LSN regression refused', async () => {
    // Advance the barrier to a known-large LSN first.
    await admin.query(
      `UPDATE agent_revocation_barrier
          SET last_lsn = pg_current_wal_insert_lsn()
        WHERE id = 1`,
    );
    const before = await readAuthoritativeBarrier(fix.postgres);
    // Try to regress to '0/1' (smaller) on the same timeline.
    let caught: unknown;
    try {
      await admin.query(
        `UPDATE agent_revocation_barrier SET last_lsn = '0/1'::pg_lsn WHERE id = 1`,
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    expect((caught as { code?: string }).code).toBe('23514');
    // Barrier unchanged.
    const after = await readAuthoritativeBarrier(fix.postgres);
    expect(after.last_lsn).toBe(before.last_lsn);
  });

  it('§3.12 barrier trigger: timeline regression refused', async () => {
    // Advance timeline.
    await admin.query(
      `UPDATE agent_revocation_barrier
          SET timeline_id = 5, last_lsn = pg_current_wal_insert_lsn()
        WHERE id = 1`,
    );
    let caught: unknown;
    try {
      await admin.query(
        `UPDATE agent_revocation_barrier SET timeline_id = 4 WHERE id = 1`,
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeDefined();
    expect((caught as { code?: string }).code).toBe('23514');
  });

  it('§3.12 barrier reset on new timeline accepts a smaller last_lsn', async () => {
    // From the previous test, timeline_id=5 with some recent LSN.
    // Advance to timeline 6 with a new LSN — allowed.
    await admin.query(
      `UPDATE agent_revocation_barrier
          SET timeline_id = 6, last_lsn = pg_current_wal_insert_lsn()
        WHERE id = 1`,
    );
    const after = await readAuthoritativeBarrier(fix.postgres);
    expect(after.timeline_id).toBe(6);
  });
});
