import { describe, it, expect } from 'vitest';
import { JitRbac } from '../../src/admin/jit-rbac.js';

describe('JitRbac (SPEC §8.1 admin.jit_rbac)', () => {
  it('grants a time-bounded role and assertGrant succeeds before expiry', () => {
    let now = 1000;
    const rbac = new JitRbac({ now: () => now, default_ttl_seconds: 60 });
    const grant = rbac.grant({
      admin_id: 'a',
      role: 'agent_auth_admin',
      reason: 'incident-12345',
    });
    expect(grant.expires_at - grant.granted_at).toBe(60_000);
    expect(rbac.assertGrant(grant.grant_id, 'agent_auth_admin')).toMatchObject({
      grant_id: grant.grant_id,
    });
  });

  it('rejects after expiry', () => {
    let now = 0;
    const rbac = new JitRbac({ now: () => now });
    const g = rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'incident-12' });
    now = g.expires_at + 1;
    expect(() => rbac.assertGrant(g.grant_id, 'agent_auth_admin')).toThrow(/expired/);
  });

  it('rejects role mismatch', () => {
    const rbac = new JitRbac();
    const g = rbac.grant({ admin_id: 'a', role: 'agent_auth_readonly', reason: 'incident-99' });
    expect(() => rbac.assertGrant(g.grant_id, 'agent_auth_admin')).toThrow(/role_mismatch/);
  });

  it('rejects too-short reason', () => {
    const rbac = new JitRbac();
    expect(() =>
      rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'x' }),
    ).toThrow();
  });

  it('caps ttl at max_ttl', () => {
    const rbac = new JitRbac({ max_ttl_seconds: 60 });
    const g = rbac.grant({
      admin_id: 'a',
      role: 'agent_auth_admin',
      reason: 'long-grant',
      ttl_seconds: 99999,
    });
    expect(g.expires_at - g.granted_at).toBe(60_000);
  });

  it('rejects non-finite ttl_seconds (NaN, Infinity, negative) — RT-10 defense in depth', async () => {
    // A NaN or non-positive ttl makes expires_at = NaN, which slips past
    // the `expires_at <= now()` check (NaN comparisons are always false)
    // and produces an effectively-immortal grant. SPEC §8.1 caps grants
    // at 4h max; the defense must reject anything that bypasses that cap.
    const rbac = new JitRbac();
    expect(() =>
      rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'reason123', ttl_seconds: Number.NaN }),
    ).toThrow(/ttl_seconds/);
    expect(() =>
      rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'reason123', ttl_seconds: 0 }),
    ).toThrow(/ttl_seconds/);
    expect(() =>
      rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'reason123', ttl_seconds: -1 }),
    ).toThrow(/ttl_seconds/);
    // +Infinity is safe (Math.min caps it) but also rejected for clarity.
    expect(() =>
      rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'reason123', ttl_seconds: Number.POSITIVE_INFINITY }),
    ).toThrow(/ttl_seconds/);
  });

  it('revoke removes the grant and emits audit', () => {
    const events: Array<{ kind: string }> = [];
    const rbac = new JitRbac({ onAudit: (e) => events.push({ kind: e.kind }) });
    const g = rbac.grant({ admin_id: 'a', role: 'agent_auth_admin', reason: 'incident' });
    rbac.revoke(g.grant_id);
    expect(rbac.size()).toBe(0);
    expect(events).toEqual([{ kind: 'granted' }, { kind: 'revoked' }]);
  });
});
