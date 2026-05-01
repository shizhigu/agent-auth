/**
 * Unit tests for the optional redirect_uri_allowlist defense-in-depth.
 *
 * The OAuth provider already enforces its own redirect_uri allowlist
 * (registered URIs in the GitHub / Google App config). This second
 * gate catches misconfiguration where a SaaS team registers preview
 * + production redirects in the same OAuth app and accidentally lets
 * an unintended redirect through.
 *
 * The allowlist is checked at factory construction (not at request
 * time) so misconfigurations fail-fast on startup, not on first
 * registration attempt.
 */
import { describe, it, expect } from 'vitest';
import { vouch } from '../../src/factory.js';

describe('vouch() — redirect_uri_allowlist', () => {
  const baseConfig = {
    database: { url: 'postgres://stub' },
    redis: { url: 'redis://stub' },
    kms: { provider: 'in-memory' as const },
    identity: {
      github: { client_id: 'c', client_secret: 's' },
    },
    internal_secret: Buffer.alloc(32),
  };

  it('passes when redirect_uri matches an allowlist origin exactly', async () => {
    // We only get to test the construction-time check — we won't await
    // the full vouch() because that connects to Redis. Instead we
    // assert the synchronous validation throws or doesn't throw.
    // The throw happens before redis.loadScripts(); the test gives up
    // and times out otherwise. Use a Promise.race with a short timer.
    const promise = vouch({
      ...baseConfig,
      base_url: 'https://api.acme.com',
      redirect_uri_allowlist: ['https://api.acme.com'],
    });
    // Don't await — we just need to confirm no synchronous throw.
    // If allowlist validation passed, the promise will eventually
    // reject at redis.loadScripts() — which is fine.
    await expect(Promise.race([promise, sleepReject(100)])).rejects.not.toThrow(
      /redirect_uri_allowlist|doesn't match/,
    );
  });

  it('throws when redirect_uri does not match any allowlist entry', async () => {
    await expect(
      vouch({
        ...baseConfig,
        base_url: 'https://attacker.example.com',
        redirect_uri_allowlist: ['https://api.acme.com'],
      }),
    ).rejects.toThrow(/redirect_uri.*doesn't match.*allowlist/);
  });

  it('matches a path prefix on the allowlist', async () => {
    const promise = vouch({
      ...baseConfig,
      base_url: 'https://api.acme.com',
      redirect_uri_allowlist: ['https://api.acme.com/agent-auth'],
    });
    await expect(Promise.race([promise, sleepReject(100)])).rejects.not.toThrow(
      /redirect_uri_allowlist/,
    );
  });

  it('rejects when origin matches but path is outside the prefix', async () => {
    await expect(
      vouch({
        ...baseConfig,
        base_url: 'https://api.acme.com',
        // Forces redirect_uri to be /agent-auth/callback; allowlist
        // requires /api/* — should fail.
        mount_path: '/agent-auth',
        redirect_uri_allowlist: ['https://api.acme.com/api'],
      }),
    ).rejects.toThrow(/redirect_uri.*doesn't match/);
  });

  it('skips the check when redirect_uri_allowlist is undefined', async () => {
    // No allowlist → no validation. Promise will reject only at
    // redis.loadScripts() (which we don't reach in this test).
    const promise = vouch({
      ...baseConfig,
      base_url: 'https://anywhere.example',
    });
    await expect(Promise.race([promise, sleepReject(100)])).rejects.not.toThrow(
      /redirect_uri/,
    );
  });
});

function sleepReject(ms: number): Promise<never> {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error('timeout — synchronous validation passed')), ms),
  );
}
