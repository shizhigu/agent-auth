/**
 * Integration: tombstone reapply after a backup restore. SPEC §6.2.2 / RT-23 /
 * RT-40.
 *
 * Scenario:
 *   1. Snapshot the cluster at time T (we capture the row counts in our
 *      test by recording state at a checkpoint).
 *   2. After T, more revocations land. agent_revocation_log captures
 *      every revoke with a commit_lsn.
 *   3. A backup-restore brings the cluster back to time T (we simulate by
 *      directly reverting one of the post-T revocations).
 *   4. The post-T agent_revocation_log entries are still present in the
 *      cross-region log (or, in single-region, written to S3 outside the
 *      DB). Operator replays them — RT-23/RT-40 mitigation.
 *   5. Verify the reverted key ends up in the revoked state again after
 *      the replay.
 *
 * The §3.11 design intent is that `agent_revocation_log` IS the tombstone
 * source of truth for restoration; this test exercises the replay logic.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface RevocationLogRow {
  ts: Date;
  region: string;
  kind: 'key_revoke' | 'account_suspend' | 'identity_revoke' | 'emergency_rotate' | 'account_close';
  target_id: string;
  commit_lsn: string;
  epoch: string;
  reason: string | null;
}

async function reapplyTombstones(
  pg: PostgresAdapter,
  rows: ReadonlyArray<RevocationLogRow>,
): Promise<{ reapplied: number }> {
  let reapplied = 0;
  for (const row of rows) {
    if (row.kind === 'key_revoke') {
      const r = await pg.query(
        `UPDATE agent_api_keys
            SET rotation_state = 'revoked',
                revoked_at = COALESCE(revoked_at, $2),
                revoked_reason = COALESCE(revoked_reason, $3)
          WHERE key_id = $1
            AND rotation_state IN ('active', 'rotating')`,
        [row.target_id, row.ts, row.reason ?? 'tombstone_reapply'],
      );
      if (r.rowCount > 0) reapplied++;
    } else if (row.kind === 'account_suspend') {
      const r = await pg.query(
        `UPDATE agent_accounts
            SET status = 'suspended',
                suspended_at = COALESCE(suspended_at, $2)
          WHERE id = $1::uuid AND status = 'active'`,
        [row.target_id, row.ts],
      );
      if (r.rowCount > 0) reapplied++;
    } else if (row.kind === 'identity_revoke') {
      const r = await pg.query(
        `UPDATE agent_identities
            SET status = 'revoked',
                revoked_at = COALESCE(revoked_at, $2),
                revoked_reason = COALESCE(revoked_reason, $3),
                revocation_source = COALESCE(revocation_source, 'cascade')
          WHERE subject = $1 AND status = 'active'`,
        [row.target_id, row.ts, row.reason ?? 'tombstone_reapply'],
      );
      if (r.rowCount > 0) reapplied++;
    }
  }
  return { reapplied };
}

describe('integration: tombstone reapply (SPEC §6.2.2 / RT-23 / RT-40)', () => {
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

  it('reapplies post-snapshot revocations from agent_revocation_log', async () => {
    // Seed account + identity + 3 keys.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('rt23-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'rt23-1', 'Iv1.x', 'github.com', 'medium',
                 'rt23-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const key_ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const secret = randomBytes(32);
      const pepper = await fix.kms.getCurrentPepper();
      const key_hash = hmacWithPepper(pepper.data, secret);
      const key_id = `agk_rt23_${i}`;
      await fix.postgres.query(
        `INSERT INTO agent_api_keys
           (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
            prefix, scopes, tier, version, rotation_state)
           VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
        [
          acc!.id,
          ident!.id,
          key_id,
          key_hash,
          pepper.version,
          secret.toString('base64url').slice(0, 8),
        ],
      );
      key_ids.push(key_id);
    }

    // Revoke key_ids[0] + key_ids[1] (these are POST-snapshot revocations).
    for (const kid of key_ids.slice(0, 2)) {
      await fix.postgres.query(
        `UPDATE agent_api_keys
            SET rotation_state = 'revoked', revoked_at = now(),
                revoked_reason = 'pre_restore'
          WHERE key_id = $1`,
        [kid],
      );
      // Append the tombstone to the cross-region revocation log.
      await fix.postgres.query(
        `INSERT INTO agent_revocation_log
           (region, kind, target_id, commit_lsn, epoch, reason)
         VALUES ('us-east-1', 'key_revoke', $1, pg_current_wal_insert_lsn(),
                 (SELECT epoch FROM agent_revocation_epoch WHERE id = 1),
                 'pre_restore')`,
        [kid],
      );
    }

    // Snapshot revocation_log to capture post-snapshot tombstones.
    const tombstones = await admin.query<RevocationLogRow>(
      `SELECT ts, region, kind, target_id, commit_lsn::text AS commit_lsn,
              epoch::text AS epoch, reason
         FROM agent_revocation_log
        WHERE target_id = ANY($1::text[])
        ORDER BY id ASC`,
      [key_ids],
    );

    // Simulate restore by reverting key_ids[0] back to active (this is the
    // hostile case — the restore brought back a state that should remain
    // revoked).
    await admin.query(
      `UPDATE agent_api_keys
          SET rotation_state = 'active', revoked_at = NULL,
              revoked_reason = NULL
        WHERE key_id = $1`,
      [key_ids[0]],
    );
    const checkRevived = await admin.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_ids[0]],
    );
    expect(checkRevived?.rotation_state).toBe('active');

    // RT-23/RT-40 mitigation: reapply tombstones from the revocation log.
    const { reapplied } = await reapplyTombstones(admin, tombstones.rows);
    // key_ids[0] was reverted → reapply finds it active → revokes it again.
    // key_ids[1] was already revoked → no row affected.
    expect(reapplied).toBe(1);

    const after = await admin.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_ids[0]],
    );
    expect(after?.rotation_state).toBe('revoked');

    // Idempotent: a second reapply pass should be a no-op.
    const second = await reapplyTombstones(admin, tombstones.rows);
    expect(second.reapplied).toBe(0);

    // Untouched key (key_ids[2]) remains active.
    const untouched = await admin.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_ids[2]],
    );
    expect(untouched?.rotation_state).toBe('active');
  });
});
