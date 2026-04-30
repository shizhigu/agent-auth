import { describe, it, expect } from 'vitest';
import { LocalCache } from '../../src/cache/local-cache.js';
import type { KeyCache } from '../../src/types.js';

function entry(key_id: string, t = 1000, ttl = 30_000): KeyCache {
  return {
    key_id,
    account_id: 'a',
    account_status: 'active',
    issuing_identity_id: 'i',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: 's',
    identity_assurance_level: 'medium',
    key_hash: Buffer.alloc(32),
    key_pepper_version: 1,
    scopes: ['read'],
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    grace_expires_at: null,
    expires_at: null,
    cached_epoch: 1,
    cached_at: t,
    redis_expires_at: t + ttl,
  };
}

describe('LocalCache (SPEC §5.3.1)', () => {
  it('hits when entry not expired', () => {
    let now = 1000;
    const c = new LocalCache({ now: () => now });
    c.set('agk_a', entry('agk_a', 1000));
    now = 5000;
    expect(c.get('agk_a')?.key_id).toBe('agk_a');
  });

  it('evicts expired entry on get and returns null', () => {
    let now = 1000;
    const c = new LocalCache({ now: () => now });
    c.set('agk_a', entry('agk_a', 1000));
    now = 1000 + 30_000;
    expect(c.get('agk_a')).toBeNull();
    expect(c.size()).toBe(0);
  });

  it('LRU evicts oldest when over capacity', () => {
    const t = 1000;
    const c = new LocalCache({ capacity: 3, now: () => t });
    c.set('a', entry('a', t));
    c.set('b', entry('b', t));
    c.set('c', entry('c', t));
    c.set('d', entry('d', t));
    expect(c.keys()).toEqual(['b', 'c', 'd']);
  });

  it('LRU bumps recently-touched entries to end', () => {
    const t = 1000;
    const c = new LocalCache({ capacity: 3, now: () => t });
    c.set('a', entry('a', t));
    c.set('b', entry('b', t));
    c.set('c', entry('c', t));
    c.get('a');
    c.set('d', entry('d', t));
    // 'b' should be evicted, not 'a'
    expect(c.keys()).toEqual(['c', 'a', 'd']);
  });

  it('delete removes entry', () => {
    const c = new LocalCache();
    c.set('a', entry('a'));
    c.delete('a');
    expect(c.get('a')).toBeNull();
  });

  it('respects redis_expires_at independent of ttl_ms ceiling', () => {
    let now = 1000;
    const c = new LocalCache({ now: () => now, ttl_ms: 60_000 });
    c.set('a', entry('a', 1000, 5_000)); // redis_expires_at = 6000
    now = 6500;
    expect(c.get('a')).toBeNull();
  });
});
