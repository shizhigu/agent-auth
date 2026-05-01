/**
 * Integration: expired-rows reaper (SPEC §3.14 + §5.1.1).
 *
 * Plants approval + idempotency rows with mixed expiries / states,
 * runs reapExpiredRows, asserts only the past-grace + terminal rows
 * are deleted while in-flight idempotency rows survive.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { reapExpiredRows } from '../../src/jobs/expired-rows-reaper.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

describe('integration: reapExpiredRows (SPEC §3.14 + §5.1.1)', () => {
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
  }, 240_000);

  afterAll(async () => {
    await admin?.close().catch(() => undefined);
    await fix.cleanup();
  }, 120_000);

  it('drops expired terminal rows; preserves fresh + non-terminal idempotency rows', async () => {
    // Need an account so the FK on agent_recovery_approvals is satisfied.
    const acc = await admin.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('reaper-acc', 'cold', 'active') RETURNING id::text AS id`,
    );

    // 1) Expired approval (24h+2h ago) — should be deleted.
    await admin.query(
      `INSERT INTO agent_recovery_approvals
         (request_id, account_id, poll_token, approval_url_token,
          webhook_nonce, webhook_sent_at, decision, expires_at)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5,
               now() - interval '26 hours', 'denied',
               now() - interval '2 hours')`,
      [
        randomUUID(),
        acc!.id,
        'pkr_expired_' + randomBytes(20).toString('base64url'),
        'aut_expired_' + randomBytes(16).toString('base64url'),
        randomBytes(32),
      ],
    );
    // 2) Fresh approval (expires in 23h) — survives.
    const freshToken = 'aut_fresh_' + randomBytes(16).toString('base64url');
    await admin.query(
      `INSERT INTO agent_recovery_approvals
         (request_id, account_id, poll_token, approval_url_token,
          webhook_nonce, webhook_sent_at, decision, expires_at)
       VALUES ($1::uuid, $2::uuid, $3, $4, $5,
               now(), 'pending', now() + interval '23 hours')`,
      [
        randomUUID(),
        acc!.id,
        'pkr_fresh_' + randomBytes(20).toString('base64url'),
        freshToken,
        randomBytes(32),
      ],
    );

    // 3) Expired idempotency in TERMINAL state (completed) — should be deleted.
    await admin.query(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, expires_at,
          outcome_status, outcome_body)
       VALUES ('idk_done_' || $1, $2, 'revoke', 'key:agk_x', 'completed',
               now() - interval '2 hours', 200, '{}'::jsonb)`,
      [randomBytes(8).toString('hex'), randomBytes(32)],
    );
    // 4) Expired idempotency still in 'pending' — preserved (the
    //    reconciler still owns these even past expiry).
    const pendingKey = 'idk_pending_' + randomBytes(8).toString('hex');
    await admin.query(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, expires_at)
       VALUES ($1, $2, 'revoke', 'key:agk_y', 'pending',
               now() - interval '2 hours')`,
      [pendingKey, randomBytes(32)],
    );
    // 5) Fresh idempotency (any state) — survives by date.
    const freshKey = 'idk_fresh_' + randomBytes(8).toString('hex');
    await admin.query(
      `INSERT INTO agent_idempotency
         (key, request_hash, operation_type, resource_ref, state, expires_at)
       VALUES ($1, $2, 'revoke', 'key:agk_z', 'pending',
               now() + interval '23 hours')`,
      [freshKey, randomBytes(32)],
    );

    const out = await reapExpiredRows({ postgres: admin });
    expect(out.recovery_approvals_deleted).toBeGreaterThanOrEqual(1);
    expect(out.idempotency_deleted).toBeGreaterThanOrEqual(1);

    // Survivors:
    const fresh = await admin.queryOne<{ approval_url_token: string }>(
      `SELECT approval_url_token FROM agent_recovery_approvals
        WHERE approval_url_token = $1`,
      [freshToken],
    );
    expect(fresh?.approval_url_token).toBe(freshToken);
    const pending = await admin.queryOne<{ key: string }>(
      `SELECT key FROM agent_idempotency WHERE key = $1`,
      [pendingKey],
    );
    expect(pending?.key).toBe(pendingKey);
    const freshIdem = await admin.queryOne<{ key: string }>(
      `SELECT key FROM agent_idempotency WHERE key = $1`,
      [freshKey],
    );
    expect(freshIdem?.key).toBe(freshKey);
  });
});
