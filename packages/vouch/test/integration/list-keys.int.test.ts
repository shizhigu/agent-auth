/**
 * Integration: GET /api/agent-auth/keys against real Postgres.
 * SPEC §10.1.
 *
 *   - happy path: returns active + rotating keys for the caller's account
 *     with the §10.1 projection shape; revoked keys are excluded
 *   - cross-account guard: a caller authenticated against acct-A cannot
 *     enumerate acct-B keys even with admin:keys
 *   - 403 insufficient_scope when caller lacks admin:keys
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { listKeys } from '../../src/routes/list-keys.js';
import { buildAgentContext } from '../../src/agent-context.js';
import { AgentAuthError } from '../../src/errors.js';
import type { KeyCache } from '../../src/types.js';

function makeCaller(account_id: string, scopes: string[]) {
  const cache: KeyCache = {
    key_id: `agk_caller_${account_id.slice(0, 4)}`,
    account_id,
    account_status: 'active',
    issuing_identity_id: 'ident-1',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: '777',
    identity_assurance_level: 'medium',
    key_hash: Buffer.alloc(32),
    key_pepper_version: 1,
    scopes,
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    grace_expires_at: null,
    expires_at: null,
    cached_epoch: 1,
    cached_at: 0,
    redis_expires_at: 0,
  };
  return buildAgentContext(cache);
}

describe('integration: list-keys (SPEC §10.1)', () => {
  let fix: IntegrationFixture;
  let acctA: string;
  let acctB: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    const a = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('lk-A', 'cold', 'active') RETURNING id`,
    );
    const b = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('lk-B', 'cold', 'active') RETURNING id`,
    );
    acctA = a!.id;
    acctB = b!.id;
    const idA = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'lk-A-1', 'Iv1.lk', 'github.com',
                 'medium', 'lk-A-octo', true, 'active') RETURNING id`,
      [acctA],
    );
    const idB = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'lk-B-1', 'Iv1.lk', 'github.com',
                 'medium', 'lk-B-octo', true, 'active') RETURNING id`,
      [acctB],
    );
    // 2 active + 1 rotating + 1 revoked on A; 1 active on B.
    const seedKey = async (
      account_id: string,
      identity_id: string,
      key_id: string,
      label: string | null,
      rotation_state: string,
      rotation_grace_expires_at: Date | null = null,
    ) => {
      const revoked_at = rotation_state === 'revoked' ? new Date() : null;
      await fix.postgres.query(
        `INSERT INTO agent_api_keys
           (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
            prefix, label, scopes, tier, version, rotation_state,
            rotation_grace_expires_at, revoked_at)
         VALUES ($1, $2, $3, $4, 1, $5, $6, ARRAY['read','admin:keys'], 'cold', 1,
                 $7::rotation_state_enum, $8, $9)`,
        [
          account_id,
          identity_id,
          key_id,
          Buffer.from(key_id.padEnd(32, 'x')),
          key_id.slice(0, 8),
          label,
          rotation_state,
          rotation_grace_expires_at,
          revoked_at,
        ],
      );
    };
    await seedKey(acctA, idA!.id, 'agk_lkA1', 'laptop', 'active');
    await seedKey(acctA, idA!.id, 'agk_lkA2', 'desktop', 'active');
    await seedKey(
      acctA,
      idA!.id,
      'agk_lkA3',
      'rotated',
      'rotating',
      new Date(Date.now() + 60 * 60 * 1000),
    );
    await seedKey(acctA, idA!.id, 'agk_lkAR', 'gone', 'revoked');
    await seedKey(acctB, idB!.id, 'agk_lkB1', 'B-laptop', 'active');
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  it('happy path: returns active + rotating keys, excludes revoked, applies §10.1 shape', async () => {
    const caller = makeCaller(acctA, ['read', 'admin:keys']);
    const out = await listKeys({ caller, postgres: fix.postgres });
    const keyIds = out.keys.map((k) => k.key_id).sort();
    expect(keyIds).toEqual(['agk_lkA1', 'agk_lkA2', 'agk_lkA3']);
    const a1 = out.keys.find((k) => k.key_id === 'agk_lkA1');
    expect(a1?.label).toBe('laptop');
    expect(a1?.tier).toBe('cold');
    expect(a1?.rotation_state).toBe('active');
    expect(a1?.scopes).toContain('admin:keys');
    expect(typeof a1?.created_at).toBe('string');
    // ISO 8601 with milliseconds + Z suffix.
    expect(a1?.created_at).toMatch(/Z$/);
    expect(a1?.expires_at).toBeNull();
  });

  it('cross-account guard: caller from acct-A never sees acct-B keys', async () => {
    const callerA = makeCaller(acctA, ['admin:keys']);
    const out = await listKeys({ caller: callerA, postgres: fix.postgres });
    const ids = out.keys.map((k) => k.key_id);
    expect(ids).not.toContain('agk_lkB1');
  });

  it('403 insufficient_scope when caller lacks admin:keys', async () => {
    const caller = makeCaller(acctA, ['read', 'self:rotate']);
    await expect(
      listKeys({ caller, postgres: fix.postgres }),
    ).rejects.toBeInstanceOf(AgentAuthError);
    await expect(
      listKeys({ caller, postgres: fix.postgres }),
    ).rejects.toMatchObject({ status: 403, code: 'insufficient_scope' });
  });
});
