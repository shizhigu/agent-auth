/**
 * Unit: GET /api/agent-auth/keys (SPEC §10.1).
 *
 *   - 403 when the caller lacks `admin:keys`
 *   - happy path returns the SPEC-shaped projection
 *   - revoked keys excluded from the listing
 *   - cross-account guard: only the caller's account-id is queried
 */
import { describe, it, expect } from 'vitest';
import { listKeys } from '../../src/routes/list-keys.js';
import { buildAgentContext } from '../../src/agent-context.js';
import { AgentAuthError } from '../../src/errors.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { KeyCache } from '../../src/types.js';

interface FakeKeyRow {
  key_id: string;
  prefix: string;
  label: string | null;
  scopes: string[];
  tier: 'cold' | 'warm' | 'hot';
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked';
  created_at: Date;
  last_used_at: Date | null;
  expires_at: Date | null;
  account_id: string;
}

class FakePg {
  capturedSql = '';
  capturedParams: ReadonlyArray<unknown> = [];
  rows: FakeKeyRow[];
  constructor(rows: FakeKeyRow[]) {
    this.rows = rows;
  }
  async query<R>(text: string, params?: ReadonlyArray<unknown>) {
    this.capturedSql = text;
    this.capturedParams = params ?? [];
    const accountId = (params?.[0] ?? '') as string;
    const filtered = this.rows
      .filter((r) => r.account_id === accountId && r.rotation_state !== 'revoked')
      .map((r) => ({
        key_id: r.key_id,
        prefix: r.prefix,
        label: r.label,
        scopes: r.scopes,
        tier: r.tier,
        rotation_state: r.rotation_state,
        created_at: r.created_at,
        last_used_at: r.last_used_at,
        expires_at: r.expires_at,
      }));
    return { rows: filtered as unknown as R[], rowCount: filtered.length };
  }
}

function makeCaller(scopes: string[]): ReturnType<typeof buildAgentContext> {
  const cache: KeyCache = {
    key_id: 'agk_caller',
    account_id: 'acct-A',
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

describe('listKeys (SPEC §10.1)', () => {
  it('rejects 403 insufficient_scope when caller lacks admin:keys', async () => {
    const pg = new FakePg([]);
    const caller = makeCaller(['read', 'self:rotate']);
    await expect(
      listKeys({ caller, postgres: pg as unknown as PostgresAdapter }),
    ).rejects.toBeInstanceOf(AgentAuthError);
    await expect(
      listKeys({ caller, postgres: pg as unknown as PostgresAdapter }),
    ).rejects.toMatchObject({
      status: 403,
      code: 'insufficient_scope',
      details: { required: 'admin:keys' },
    });
  });

  it('returns the §10.1 projection and excludes revoked keys', async () => {
    const t0 = new Date('2026-04-30T12:00:00Z');
    const t1 = new Date('2026-04-30T13:00:00Z');
    const pg = new FakePg([
      {
        account_id: 'acct-A',
        key_id: 'agk_aa',
        prefix: 'aaaaaaaa',
        label: 'claude-code-laptop',
        scopes: ['read', 'self:rotate', 'admin:keys'],
        tier: 'cold',
        rotation_state: 'active',
        created_at: t0,
        last_used_at: t1,
        expires_at: null,
      },
      {
        account_id: 'acct-A',
        key_id: 'agk_revoked',
        prefix: 'revrevre',
        label: null,
        scopes: ['read'],
        tier: 'cold',
        rotation_state: 'revoked',
        created_at: t0,
        last_used_at: null,
        expires_at: null,
      },
      // Different account — must NOT leak.
      {
        account_id: 'acct-B',
        key_id: 'agk_other',
        prefix: 'bbbbbbbb',
        label: 'other',
        scopes: ['read'],
        tier: 'cold',
        rotation_state: 'active',
        created_at: t0,
        last_used_at: null,
        expires_at: null,
      },
    ]);
    const caller = makeCaller(['read', 'admin:keys']);
    const out = await listKeys({ caller, postgres: pg as unknown as PostgresAdapter });
    expect(out.keys).toHaveLength(1);
    expect(out.keys[0]).toEqual({
      key_id: 'agk_aa',
      prefix: 'aaaaaaaa',
      label: 'claude-code-laptop',
      scopes: ['read', 'self:rotate', 'admin:keys'],
      tier: 'cold',
      rotation_state: 'active',
      created_at: '2026-04-30T12:00:00.000Z',
      last_used_at: '2026-04-30T13:00:00.000Z',
      expires_at: null,
    });
    // Cross-account guard: WHERE account_id = caller.account_id is the only param.
    expect(pg.capturedParams[0]).toBe('acct-A');
  });

  it('returns empty array for an account with no active keys', async () => {
    const pg = new FakePg([]);
    const caller = makeCaller(['admin:keys']);
    const out = await listKeys({ caller, postgres: pg as unknown as PostgresAdapter });
    expect(out.keys).toEqual([]);
  });
});
