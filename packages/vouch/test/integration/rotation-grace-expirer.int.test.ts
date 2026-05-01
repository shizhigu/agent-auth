/**
 * Integration: rotation-grace-expirer (SPEC §2.7.3).
 *
 * Plants two 'rotating' keys — one with grace already past, one with
 * grace still in the future. The job flips only the past one.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { expireRotationGrace } from '../../src/jobs/rotation-grace-expirer.js';

describe('integration: rotation-grace-expirer (SPEC §2.7.3)', () => {
  let fix: IntegrationFixture;
  let acct: string;
  let ident: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    const a = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('grace-acc', 'cold', 'active') RETURNING id`,
    );
    const i = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'grace-1', 'Iv1.gr', 'github.com',
                 'medium', 'grace-octo', true, 'active') RETURNING id`,
      [a!.id],
    );
    acct = a!.id;
    ident = i!.id;
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('flips only rotating keys with grace already past', async () => {
    const past = new Date(Date.now() - 60 * 1000); // 1 min ago
    const future = new Date(Date.now() + 60 * 60 * 1000); // 1 h from now

    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash,
          key_pepper_version, prefix, scopes, tier, version, rotation_state,
          rotated_at, rotation_grace_expires_at)
       VALUES ($1, $2, 'agk_grace_past', $3, 1, 'pastpast', '{"read"}',
               'cold', 1, 'rotating', now(), $4)`,
      [acct, ident, Buffer.alloc(32, 1), past],
    );
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash,
          key_pepper_version, prefix, scopes, tier, version, rotation_state,
          rotated_at, rotation_grace_expires_at)
       VALUES ($1, $2, 'agk_grace_future', $3, 1, 'futurefu', '{"read"}',
               'cold', 1, 'rotating', now(), $4)`,
      [acct, ident, Buffer.alloc(32, 2), future],
    );

    const out = await expireRotationGrace({ postgres: fix.postgres });
    expect(out.expired).toBe(1);

    const past_row = await fix.postgres.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = 'agk_grace_past'`,
    );
    const future_row = await fix.postgres.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = 'agk_grace_future'`,
    );
    expect(past_row?.rotation_state).toBe('rotated');
    expect(future_row?.rotation_state).toBe('rotating');
  });

  it('idempotent: re-run finds nothing to expire', async () => {
    const out = await expireRotationGrace({ postgres: fix.postgres });
    expect(out.expired).toBe(0);
  });

  it('emits onAlert with first_key_id when batch is non-empty', async () => {
    const past = new Date(Date.now() - 30 * 1000);
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash,
          key_pepper_version, prefix, scopes, tier, version, rotation_state,
          rotated_at, rotation_grace_expires_at)
       VALUES ($1, $2, 'agk_grace_alert', $3, 1, 'alertale', '{"read"}',
               'cold', 1, 'rotating', now(), $4)`,
      [acct, ident, Buffer.alloc(32, 3), past],
    );
    const alerts: Array<{ label: string; meta: Record<string, unknown> }> = [];
    const out = await expireRotationGrace({
      postgres: fix.postgres,
      onAlert: (label, meta) => alerts.push({ label, meta }),
    });
    expect(out.expired).toBe(1);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]!.label).toBe('rotation_grace_expired_batch');
    expect(alerts[0]!.meta).toMatchObject({
      count: 1,
      first_key_id: 'agk_grace_alert',
    });
  });
});
