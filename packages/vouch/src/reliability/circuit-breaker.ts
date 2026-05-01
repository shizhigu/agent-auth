/**
 * Circuit breaker for upstream IdP calls. SPEC §5.4.
 *
 * State machine:
 *   closed   → all requests pass through; failures counted in a rolling window
 *   open     → reject immediately with `idp_circuit_open` until halfOpenAfter
 *   half-open → allow up to `halfOpenProbeCount` probes; success closes,
 *               failure re-opens for another halfOpenAfter
 *
 * When a request is rejected (open or half-open exhausted) the breaker
 * throws ServiceUnavailableError(idp_circuit_open).
 */

import { ServiceUnavailableError } from '../errors.js';

export type CircuitState = 'closed' | 'open' | 'half_open';

export interface CircuitBreakerOptions {
  readonly failureThreshold?: number; // default 5
  readonly failureWindow?: number; // ms, default 60_000
  readonly halfOpenAfter?: number; // ms, default 30_000
  readonly halfOpenProbeCount?: number; // default 1
  readonly onOpen?: () => void;
  readonly onClose?: () => void;
  readonly now?: () => number;
}

export class CircuitBreaker {
  private state: CircuitState = 'closed';
  private failureTimestamps: number[] = [];
  private openSinceMs: number | null = null;
  private inflightProbes = 0;
  private readonly failureThreshold: number;
  private readonly failureWindow: number;
  private readonly halfOpenAfter: number;
  private readonly halfOpenProbeCount: number;
  private readonly onOpen?: () => void;
  private readonly onClose?: () => void;
  private readonly now: () => number;

  constructor(opts: CircuitBreakerOptions = {}) {
    this.failureThreshold = opts.failureThreshold ?? 5;
    this.failureWindow = opts.failureWindow ?? 60_000;
    this.halfOpenAfter = opts.halfOpenAfter ?? 30_000;
    this.halfOpenProbeCount = opts.halfOpenProbeCount ?? 1;
    if (opts.onOpen) this.onOpen = opts.onOpen;
    if (opts.onClose) this.onClose = opts.onClose;
    this.now = opts.now ?? Date.now;
  }

  /** Run `op` through the breaker. Throws on rejection or op error. */
  async execute<T>(op: () => Promise<T>): Promise<T> {
    this.maybeTransitionToHalfOpen();
    if (this.state === 'open') {
      throw new ServiceUnavailableError('idp_circuit_open');
    }
    if (this.state === 'half_open') {
      if (this.inflightProbes >= this.halfOpenProbeCount) {
        throw new ServiceUnavailableError('idp_circuit_open');
      }
      this.inflightProbes++;
    }
    try {
      const result = await op();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    } finally {
      if (this.state === 'half_open' && this.inflightProbes > 0) {
        this.inflightProbes--;
      }
    }
  }

  state_(): CircuitState {
    return this.state;
  }

  private maybeTransitionToHalfOpen(): void {
    if (this.state !== 'open' || this.openSinceMs === null) return;
    if (this.now() - this.openSinceMs >= this.halfOpenAfter) {
      this.state = 'half_open';
      this.inflightProbes = 0;
    }
  }

  private recordSuccess(): void {
    if (this.state === 'half_open') {
      this.toClosed();
      return;
    }
    if (this.state === 'closed') {
      // Drop stale failures from the rolling window.
      this.failureTimestamps = this.failureTimestamps.filter(
        (t) => this.now() - t < this.failureWindow,
      );
    }
  }

  private recordFailure(): void {
    const t = this.now();
    if (this.state === 'half_open') {
      this.toOpen(t);
      return;
    }
    this.failureTimestamps = this.failureTimestamps.filter(
      (x) => t - x < this.failureWindow,
    );
    this.failureTimestamps.push(t);
    if (this.failureTimestamps.length >= this.failureThreshold) {
      this.toOpen(t);
    }
  }

  private toOpen(t: number): void {
    if (this.state === 'open') return;
    this.state = 'open';
    this.openSinceMs = t;
    this.failureTimestamps = [];
    this.onOpen?.();
  }

  private toClosed(): void {
    if (this.state === 'closed') return;
    this.state = 'closed';
    this.openSinceMs = null;
    this.failureTimestamps = [];
    this.inflightProbes = 0;
    this.onClose?.();
  }
}
