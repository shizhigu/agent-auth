import { describe, it, expect } from 'vitest';
import { tierBCommit, TierBTimeoutError } from '../../src/distributed/tier-b-commit.js';
import { ServiceUnavailableError } from '../../src/errors.js';

describe('tierBCommit (SPEC §4.3)', () => {
  it('returns the operation result on success', async () => {
    const out = await tierBCommit(async () => 42);
    expect(out).toBe(42);
  });

  it('emits 503 durability_unconfirmed on timeout', async () => {
    await expect(
      tierBCommit(
        () => new Promise((resolve) => setTimeout(() => resolve('late'), 200)),
        { timeout_ms: 20 },
      ),
    ).rejects.toMatchObject({
      status: 503,
      code: 'durability_unconfirmed',
    });
  });

  it('TierBTimeoutError surfaces as 503 (cause preserved)', async () => {
    let caught: unknown;
    try {
      await tierBCommit(
        () => new Promise<never>(() => undefined),
        { timeout_ms: 10 },
      );
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ServiceUnavailableError);
    const cause = (caught as { cause?: unknown }).cause;
    expect(cause).toBeInstanceOf(TierBTimeoutError);
  });

  it('emits 503 durability_unavailable on Postgres XX098 standby unreachable', async () => {
    await expect(
      tierBCommit(async () => {
        const e = new Error('synchronous_commit failed');
        (e as { code?: string }).code = 'XX098';
        throw e;
      }),
    ).rejects.toMatchObject({
      status: 503,
      code: 'durability_unavailable',
    });
  });

  it('passes through non-tier-B errors unchanged', async () => {
    await expect(
      tierBCommit(async () => {
        throw new Error('something else');
      }),
    ).rejects.toThrow('something else');
  });

  it('does NOT raise an unhandled rejection when the operation rejects AFTER the timeout fires', async () => {
    // Process-wide unhandledRejection listener catches anything that escapes
    // tierBCommit's late-rejection handling. If the lib forgets to swallow
    // the loser of Promise.race, this test will fail with the captured
    // rejection.
    const captured: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      captured.push(reason);
    };
    process.on('unhandledRejection', onUnhandled);
    try {
      const slowReject = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('late_rejection_after_timeout')), 30);
      });
      await expect(
        tierBCommit(() => slowReject, { timeout_ms: 5 }),
      ).rejects.toMatchObject({ code: 'durability_unconfirmed' });
      // Wait long enough for the slow rejection to fire post-timeout.
      await new Promise<void>((r) => setTimeout(r, 60));
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
    expect(captured).toHaveLength(0);
  });
});
