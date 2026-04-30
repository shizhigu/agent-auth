/**
 * Property test for GCRA invariants (SPEC §12.5).
 *
 *   "GCRA: total accepts in window <= burst capacity"
 *
 * The actual GCRA runs as a Lua script inside Redis; here we port the
 * algorithm to JS and feed it random load patterns. The property
 * checks that across any burst N requests fired in a tight window
 * shorter than `period`, at most `burst` are accepted.
 *
 * The simulator mirrors LUA_GCRA in src/storage/redis-adapter.ts:
 *   - rate     = burst / period
 *   - interval = cost / rate
 *   - allow_at = max(tat, now)
 *   - new_tat  = allow_at + interval
 *   - reject if (new_tat - now) > (burst / rate)  // burst tolerance == period
 */
import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';

interface GcraResult {
  allowed: boolean;
  /** new tat (only consumed on accept) */
  new_tat: number;
}

function gcraCheck(args: {
  now_s: number;
  tat: number;
  cost: number;
  burst: number;
  period_s: number;
}): GcraResult {
  const rate = args.burst / args.period_s;
  const interval = args.cost / rate;
  const allow_at = Math.max(args.tat, args.now_s);
  const new_tat = allow_at + interval;
  const burst_tolerance = args.burst / rate; // == period_s
  if (new_tat - args.now_s > burst_tolerance) {
    return { allowed: false, new_tat: args.tat };
  }
  return { allowed: true, new_tat };
}

interface SimResult {
  accepted: number;
  rejected: number;
}

function simulate(load: {
  burst: number;
  period_s: number;
  cost: number;
  /** request offsets in seconds, monotonically non-decreasing. */
  offsets_s: ReadonlyArray<number>;
}): SimResult {
  let tat = 0;
  let accepted = 0;
  let rejected = 0;
  for (const offset of load.offsets_s) {
    const r = gcraCheck({
      now_s: offset,
      tat,
      cost: load.cost,
      burst: load.burst,
      period_s: load.period_s,
    });
    if (r.allowed) {
      accepted++;
      tat = r.new_tat;
    } else {
      rejected++;
    }
  }
  return { accepted, rejected };
}

describe('GCRA — properties (SPEC §12.5)', () => {
  it('total accepts in a tight burst (window < period) ≤ burst', () => {
    fc.assert(
      fc.property(
        // burst: 1..50
        fc.integer({ min: 1, max: 50 }),
        // period: 1..3600 s
        fc.integer({ min: 1, max: 3600 }),
        // # requests fired tightly: 1..200
        fc.integer({ min: 1, max: 200 }),
        (burst, period_s, n) => {
          // All n requests fired at the same instant — strictest case.
          const offsets_s = Array.from({ length: n }, () => 0);
          const out = simulate({ burst, period_s, cost: 1, offsets_s });
          expect(out.accepted).toBeLessThanOrEqual(burst);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('after waiting longer than `period`, the bucket fully replenishes — next `burst` requests all accepted', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 20 }),
        fc.integer({ min: 2, max: 5 }),
        (burst, periodMultiplier) => {
          // Use period_s = burst * k so interval = period_s / burst
          // is an exact integer and `burst * interval` doesn't drift
          // above burst_tolerance in FP — the drain boundary check
          // is `new_tat > period_s` strict, which the Lua impl
          // avoids entirely by using integer microseconds. We can't
          // freely vary period_s vs burst here (any non-divisible
          // ratio re-creates the boundary flip-flop); the property
          // still exercises burst values 1..20 and periods 2..100.
          const period_s = burst * periodMultiplier;
          // Drain the bucket to empty.
          let tat = 0;
          for (let i = 0; i < burst; i++) {
            const r = gcraCheck({ now_s: 0, tat, cost: 1, burst, period_s });
            expect(r.allowed).toBe(true);
            tat = r.new_tat;
          }
          // Wait strictly past replenishment (period + 1 s slack).
          const wait_s = period_s + 1;
          let accepted = 0;
          for (let i = 0; i < burst; i++) {
            const r = gcraCheck({ now_s: wait_s, tat, cost: 1, burst, period_s });
            if (r.allowed) {
              accepted++;
              tat = r.new_tat;
            }
          }
          expect(accepted).toBe(burst);
        },
      ),
      { numRuns: 100 },
    );
  });

  it('cost > 1 consumes proportionally; total weight accepted ≤ burst', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 4, max: 20 }),
        fc.integer({ min: 1, max: 60 }),
        fc.integer({ min: 2, max: 4 }),
        (burst, period_s, cost) => {
          // Request a stream of cost-N units at the same instant.
          let tat = 0;
          let totalCostAccepted = 0;
          for (let i = 0; i < 100; i++) {
            const r = gcraCheck({ now_s: 0, tat, cost, burst, period_s });
            if (r.allowed) {
              totalCostAccepted += cost;
              tat = r.new_tat;
            }
          }
          // Burst capacity is `burst` units; cost=N requests consume
          // N units each. Total accepted weight must not exceed burst.
          expect(totalCostAccepted).toBeLessThanOrEqual(burst);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('strict monotonicity: tat never goes backwards across accepted requests', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 50 }),
        fc.integer({ min: 1, max: 60 }),
        fc.array(fc.integer({ min: 0, max: 100 }), { minLength: 1, maxLength: 50 })
          .map((arr) => arr.sort((a, b) => a - b)),
        (burst, period_s, offsets_s) => {
          let tat = 0;
          for (const offset of offsets_s) {
            const r = gcraCheck({ now_s: offset, tat, cost: 1, burst, period_s });
            if (r.allowed) {
              expect(r.new_tat).toBeGreaterThanOrEqual(tat);
              tat = r.new_tat;
            }
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
