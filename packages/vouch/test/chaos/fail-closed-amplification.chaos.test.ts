/**
 * Chaos: RT-43 fail-closed amplification. SPEC §6.2.4 / §5.4.
 *
 * When an upstream IdP (or any breaker-protected dependency) is failing,
 * the lib must NOT amplify load by retrying every failure. The
 * CircuitBreaker primitive (src/reliability/circuit-breaker.ts) absorbs
 * sustained failures: after `failureThreshold` failures within
 * `failureWindow`, the breaker opens and rejects subsequent calls
 * IMMEDIATELY without invoking the operation.
 *
 * This test floods a breaker with failing operations and asserts:
 *   - the operation is invoked exactly `failureThreshold` times before the
 *     breaker opens (no extra failed calls leak through).
 *   - subsequent calls reject as ServiceUnavailableError(idp_circuit_open)
 *     without re-invoking the operation.
 *   - on configured halfOpen window, the breaker probes once.
 */

import { describe, it, expect } from 'vitest';
import { CircuitBreaker } from '../../src/reliability/circuit-breaker.js';
import { ServiceUnavailableError } from '../../src/errors.js';

describe('chaos: fail-closed amplification (SPEC §6.2.4 / RT-43 / §5.4)', () => {
  it('breaker opens after failureThreshold; subsequent calls do not re-invoke op', async () => {
    let opCalls = 0;
    let openTransitions = 0;
    const breaker = new CircuitBreaker({
      failureThreshold: 3,
      failureWindow: 60_000,
      halfOpenAfter: 10_000,
      onOpen: () => openTransitions++,
    });
    const failing = async () => {
      opCalls++;
      throw new Error('upstream-bad');
    };
    // 100 attempts. Without the breaker, this would mean 100 op invocations.
    let rejected = 0;
    for (let i = 0; i < 100; i++) {
      try {
        await breaker.execute(failing);
      } catch (err) {
        if (err instanceof ServiceUnavailableError) rejected++;
      }
    }
    // Op invoked at most failureThreshold times before the breaker opened.
    expect(opCalls).toBe(3);
    expect(openTransitions).toBe(1);
    // Most calls were rejected immediately by the open breaker.
    expect(rejected).toBeGreaterThanOrEqual(95);
  });

  it('half-open admits exactly halfOpenProbeCount probes; success closes', async () => {
    let now = 1_000;
    let opCalls = 0;
    const breaker = new CircuitBreaker({
      failureThreshold: 1,
      failureWindow: 60_000,
      halfOpenAfter: 100,
      halfOpenProbeCount: 1,
      now: () => now,
    });
    // Open the breaker.
    await expect(
      breaker.execute(async () => {
        opCalls++;
        throw new Error('x');
      }),
    ).rejects.toThrow();
    expect(opCalls).toBe(1);
    expect(breaker.state_()).toBe('open');
    // Past halfOpenAfter — only ONE probe invokes the op.
    now += 200;
    await breaker.execute(async () => {
      opCalls++;
      return 'ok';
    });
    expect(opCalls).toBe(2);
    expect(breaker.state_()).toBe('closed');
  });

  it('flood while open does not pile up failed calls', async () => {
    let now = 1_000;
    let opCalls = 0;
    const breaker = new CircuitBreaker({
      failureThreshold: 1,
      halfOpenAfter: 60_000, // never reach half-open during the flood
      now: () => now,
    });
    await expect(
      breaker.execute(async () => {
        opCalls++;
        throw new Error('x');
      }),
    ).rejects.toThrow();
    expect(breaker.state_()).toBe('open');
    // 1000 concurrent calls — none invoke the op.
    const before = opCalls;
    await Promise.all(
      Array.from({ length: 1000 }, () =>
        breaker
          .execute(async () => {
            opCalls++;
            return 'ok';
          })
          .catch(() => undefined),
      ),
    );
    expect(opCalls).toBe(before); // op never invoked while open
  });
});
