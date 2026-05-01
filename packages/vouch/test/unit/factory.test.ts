/**
 * Unit tests for the vouch() factory's synchronous validation path.
 *
 * Anything that requires successful Redis connection (loadScripts) lives in
 * the integration tier (the demo round-trip is the canonical happy-path
 * test). Here we only verify:
 *
 *   - the factory rejects bad inputs (wrong secret length, no identity
 *     provider) before attempting any I/O
 *   - the validation runs synchronously enough that consumers don't have
 *     to wait for Redis / KMS to time out before they learn their config
 *     is broken
 */
import { describe, it, expect } from 'vitest';
import { vouch } from '../../src/factory.js';

describe('vouch() factory — input validation', () => {
  it('rejects internal_secret of wrong length', async () => {
    await expect(
      vouch({
        database: { url: 'postgres://x' },
        redis: { url: 'redis://x' },
        kms: { provider: 'in-memory' },
        identity: {},
        internal_secret: Buffer.alloc(16),
      }),
    ).rejects.toThrow(/internal_secret must be 32 bytes/);
  });

  it('rejects base64-string internal_secret that decodes to wrong length', async () => {
    await expect(
      vouch({
        database: { url: 'postgres://x' },
        redis: { url: 'redis://x' },
        kms: { provider: 'in-memory' },
        identity: {},
        internal_secret: Buffer.alloc(20).toString('base64'),
      }),
    ).rejects.toThrow(/internal_secret must be 32 bytes/);
  });

  it('rejects when no identity providers are configured', async () => {
    await expect(
      vouch({
        database: { url: 'postgres://x' },
        redis: { url: 'redis://x' },
        kms: { provider: 'in-memory' },
        identity: {},
        internal_secret: Buffer.alloc(32),
      }),
    ).rejects.toThrow(/identity must include at least one provider/);
  });

  it('validation runs before any I/O — fails fast on bad input', async () => {
    // If validation came after Redis connect, this would hang on
    // `redis://nowhere:1` for the connect timeout (~10s default). The
    // test passes in <100 ms because vouch() throws immediately on
    // input validation.
    const start = Date.now();
    await expect(
      vouch({
        database: { url: 'postgres://nowhere:1' },
        redis: { url: 'redis://nowhere:1' },
        kms: { provider: 'in-memory' },
        identity: {},
        internal_secret: Buffer.alloc(32),
      }),
    ).rejects.toThrow();
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(500);
  });
});
