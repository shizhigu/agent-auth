/**
 * Property tests for the audit hash chain (SPEC §6.4.1).
 *
 *   - A correctly-built chain of arbitrary length verifies as intact.
 *   - Tampering with any single row's prev_hash always breaks the
 *     chain at that index (i.e. verifyChain returns the right break
 *     point).
 *   - Tampering with any single row's row_hash always breaks the
 *     chain at the NEXT index (because row N's row_hash becomes
 *     row N+1's prev_hash).
 *   - Permuting rows out of order breaks the chain.
 *
 * These properties walk the linkage-only contract documented in
 * `verifyChain` (the strict byte-level recompute lives in
 * `verifyChainStrict`).
 */
import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  verifyChain,
  computeRowHash,
  ZERO_HASH,
  type AuditRow,
} from '../../src/crypto/audit-hash.js';

interface ChainRow extends AuditRow {
  prev_hash: Buffer;
  row_hash: Buffer;
}

function buildIntactChain(events: ReadonlyArray<{ id: number; event_type: string }>): ChainRow[] {
  const rows: ChainRow[] = [];
  // Force the union (Buffer<ArrayBuffer> | Buffer<ArrayBufferLike>)
  // to land on the broader form so the assignment from computeRowHash
  // (which returns a Buffer<ArrayBufferLike>) typechecks against
  // exactOptionalPropertyTypes.
  let prev: Buffer = ZERO_HASH;
  for (const e of events) {
    const r: AuditRow = {
      id: e.id,
      ts: '2027-01-01T00:00:00.000Z',
      event_type: e.event_type,
    };
    const row_hash: Buffer = computeRowHash(prev, r);
    rows.push({ ...r, prev_hash: prev, row_hash });
    prev = row_hash;
  }
  return rows;
}

const ChainArb = fc.array(
  fc.record({
    id: fc.integer({ min: 1, max: 1_000_000 }),
    event_type: fc.constantFrom('test_a', 'test_b', 'test_c'),
  }),
  { minLength: 1, maxLength: 30 },
);

describe('audit hash chain — properties (SPEC §6.4.1)', () => {
  it('a correctly-built chain of any length verifies intact', () => {
    fc.assert(
      fc.property(ChainArb, (events) => {
        const chain = buildIntactChain(events);
        expect(verifyChain(chain, ZERO_HASH)).toBe(-1);
      }),
      { numRuns: 200 },
    );
  });

  it('tampering with row[k].prev_hash breaks the chain at index k', () => {
    fc.assert(
      fc.property(
        ChainArb.filter((es) => es.length >= 2),
        fc.integer({ min: 0, max: 100 }),
        (events, idxSeed) => {
          const chain = buildIntactChain(events);
          const k = idxSeed % chain.length;
          // Replace prev_hash with a different 32-byte buffer.
          const tampered = chain.map((r, i) =>
            i === k ? { ...r, prev_hash: Buffer.alloc(32, 0xaa) } : r,
          );
          // For k = 0, the seed (ZERO_HASH) won't match 0xaa…aa.
          // For k > 0, row[k-1].row_hash won't match 0xaa…aa either.
          // Either way verifyChain should report the break at k.
          expect(verifyChain(tampered, ZERO_HASH)).toBe(k);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('tampering with row[k].row_hash breaks at index k+1 (or returns -1 if k is last)', () => {
    fc.assert(
      fc.property(
        ChainArb.filter((es) => es.length >= 2),
        fc.integer({ min: 0, max: 100 }),
        (events, idxSeed) => {
          const chain = buildIntactChain(events);
          const k = idxSeed % chain.length;
          const tampered = chain.map((r, i) =>
            i === k ? { ...r, row_hash: Buffer.alloc(32, 0xbb) } : r,
          );
          const expected = k === chain.length - 1 ? -1 : k + 1;
          expect(verifyChain(tampered, ZERO_HASH)).toBe(expected);
        },
      ),
      { numRuns: 200 },
    );
  });

  it('reversing two adjacent rows breaks the chain', () => {
    fc.assert(
      fc.property(
        ChainArb.filter((es) => es.length >= 2),
        fc.integer({ min: 0, max: 100 }),
        (events, idxSeed) => {
          const chain = buildIntactChain(events);
          const k = idxSeed % (chain.length - 1);
          const swapped = [...chain];
          [swapped[k], swapped[k + 1]] = [swapped[k + 1]!, swapped[k]!];
          // The original chain has prev[k+1] = row_hash[k]. After swap,
          // the row at position k is what was at k+1, whose prev_hash
          // points at the OLD row_hash[k] — which is now at position
          // k+1. So at position k we expect the linkage to break
          // (prev_hash[swapped[k]] doesn't match the prev row's
          // row_hash, except by accident — for k=0 the seed is
          // ZERO_HASH and swapped[0].prev_hash is the OLD row_hash[0],
          // which is some random 32 bytes).
          const breakIdx = verifyChain(swapped, ZERO_HASH);
          expect(breakIdx).toBeGreaterThanOrEqual(0);
        },
      ),
      { numRuns: 200 },
    );
  });
});
