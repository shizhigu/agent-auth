import { describe, it, expect } from 'vitest';
import { buildAgentContext } from '../../src/agent-context.js';
import { AgentAuthError } from '../../src/errors.js';
import type { KeyCache } from '../../src/types.js';

function makeCache(overrides: Partial<KeyCache> = {}): KeyCache {
  const base: KeyCache = {
    key_id: 'agk_abc12345',
    account_id: '00000000-0000-0000-0000-000000000001',
    account_status: 'active',
    issuing_identity_id: '00000000-0000-0000-0000-000000000002',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: '12345',
    identity_display_handle: 'octocat',
    identity_assurance_level: 'medium',
    key_hash: Buffer.from('00'.repeat(32), 'hex'),
    key_pepper_version: 1,
    scopes: ['read', 'self:rotate'],
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    grace_expires_at: null,
    expires_at: null,
    cached_epoch: 1,
    cached_at: 0,
    redis_expires_at: 30000,
  };
  return { ...base, ...overrides };
}

describe('buildAgentContext (SPEC §6.3)', () => {
  it('exposes account_id, key_id, identity, scopes, tier verbatim', () => {
    const ctx = buildAgentContext(makeCache());
    expect(ctx.account_id).toBe('00000000-0000-0000-0000-000000000001');
    expect(ctx.key_id).toBe('agk_abc12345');
    expect(ctx.identity).toMatchObject({
      provider: 'github_app',
      subject: '12345',
      display_handle: 'octocat',
      assurance_level: 'medium',
    });
    expect(ctx.scopes).toEqual(['read', 'self:rotate']);
    expect(ctx.tier).toBe('cold');
  });

  it('omits display_handle from identity when KeyCache does not have one', () => {
    const cache = makeCache();
    const { identity_display_handle: _drop, ...rest } = cache;
    void _drop;
    const ctx = buildAgentContext(rest as KeyCache);
    expect('display_handle' in ctx.identity).toBe(false);
  });

  it('produces a fully frozen object (RT-9 confused-deputy hardening)', () => {
    const ctx = buildAgentContext(makeCache());
    expect(Object.isFrozen(ctx)).toBe(true);
    expect(Object.isFrozen(ctx.identity)).toBe(true);
    expect(Object.isFrozen(ctx.scopes)).toBe(true);

    expect(() => {
      // @ts-expect-error — frozen
      ctx.account_id = 'tampered';
    }).toThrow();
  });

  it('has_scope returns true / false correctly', () => {
    const ctx = buildAgentContext(makeCache({ scopes: ['x', 'y'] }));
    expect(ctx.has_scope('x')).toBe(true);
    expect(ctx.has_scope('z')).toBe(false);
  });

  it('require_scope throws AgentAuthError(403, insufficient_scope) when missing', () => {
    const ctx = buildAgentContext(makeCache({ scopes: ['read'] }));
    expect(() => ctx.require_scope('write')).toThrowError(
      expect.objectContaining({
        name: 'AgentAuthError',
        status: 403,
        code: 'insufficient_scope',
      }),
    );
    try {
      ctx.require_scope('write');
    } catch (err) {
      const e = err as AgentAuthError;
      expect(e.details).toEqual({ required: 'write' });
    }
  });

  it('require_scope is silent when scope is present', () => {
    const ctx = buildAgentContext(makeCache({ scopes: ['read'] }));
    expect(() => ctx.require_scope('read')).not.toThrow();
  });

  it('builder returns a fresh scope array (does not alias caller arrays)', () => {
    const original = ['read', 'self:rotate'];
    const ctx = buildAgentContext(makeCache({ scopes: original }));
    // Mutating the source array must not affect the context.
    original.push('admin');
    expect(ctx.scopes).toEqual(['read', 'self:rotate']);
  });
});
