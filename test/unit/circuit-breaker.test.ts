import { describe, it, expect } from 'vitest';
import { CircuitBreaker } from '../../src/reliability/circuit-breaker.js';
import { ServiceUnavailableError } from '../../src/errors.js';

describe('CircuitBreaker (SPEC §5.4)', () => {
  it('passes calls through while closed', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 3 });
    expect(await breaker.execute(async () => 42)).toBe(42);
  });

  it('opens after failureThreshold consecutive failures', async () => {
    let opened = 0;
    const breaker = new CircuitBreaker({
      failureThreshold: 3,
      onOpen: () => opened++,
    });
    const failing = async () => {
      throw new Error('upstream-bad');
    };
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failing)).rejects.toThrow('upstream-bad');
    }
    expect(opened).toBe(1);
    await expect(breaker.execute(async () => 'ok')).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('transitions open → half-open after halfOpenAfter; success closes', async () => {
    let now = 1000;
    const breaker = new CircuitBreaker({
      failureThreshold: 1,
      halfOpenAfter: 100,
      now: () => now,
    });
    await expect(
      breaker.execute(async () => {
        throw new Error('x');
      }),
    ).rejects.toThrow();
    expect(breaker.state_()).toBe('open');
    now += 50;
    await expect(breaker.execute(async () => 'ok')).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    now += 200; // past halfOpenAfter
    expect(await breaker.execute(async () => 'ok')).toBe('ok');
    expect(breaker.state_()).toBe('closed');
  });

  it('half-open failure re-opens', async () => {
    let now = 1000;
    const breaker = new CircuitBreaker({
      failureThreshold: 1,
      halfOpenAfter: 50,
      now: () => now,
    });
    await expect(
      breaker.execute(async () => {
        throw new Error('x');
      }),
    ).rejects.toThrow();
    now += 100;
    await expect(
      breaker.execute(async () => {
        throw new Error('still bad');
      }),
    ).rejects.toThrow('still bad');
    expect(breaker.state_()).toBe('open');
  });

  it('failure window drops stale failures', async () => {
    let now = 0;
    const breaker = new CircuitBreaker({
      failureThreshold: 3,
      failureWindow: 1000,
      now: () => now,
    });
    const failing = async () => {
      throw new Error('x');
    };
    await expect(breaker.execute(failing)).rejects.toThrow();
    now = 2000; // past window
    await expect(breaker.execute(failing)).rejects.toThrow();
    await expect(breaker.execute(failing)).rejects.toThrow();
    expect(breaker.state_()).toBe('closed'); // first failure dropped
  });
});
