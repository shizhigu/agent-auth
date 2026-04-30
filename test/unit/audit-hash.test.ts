import { describe, it, expect } from 'vitest';
import {
  computeRowHash,
  canonicalAuditText,
  ZERO_HASH,
  verifyChain,
  sha256Hex,
} from '../../src/crypto/audit-hash.js';

describe('canonicalAuditText (mirrors SQL trigger §3.8)', () => {
  it('uses field order id, ts, event_type, account_id, key_id, endpoint, status_class, meta_hash', () => {
    const text = canonicalAuditText({
      id: 1,
      ts: '2026-04-30T12:00:00.000Z',
      event_type: 'key_validated',
      account_id: 'acc',
      key_id: 'agk_x',
      endpoint: '/api/foo',
      status_class: 2,
      meta: { reason: 'ok' },
    });
    // The fields must appear in the exact order the trigger uses.
    const expectedOrder = [
      '"id"',
      '"ts"',
      '"event_type"',
      '"account_id"',
      '"key_id"',
      '"endpoint"',
      '"status_class"',
      '"meta_hash"',
    ];
    let lastIdx = -1;
    for (const f of expectedOrder) {
      const i = text.indexOf(f);
      expect(i, `${f} must appear in canonical text`).toBeGreaterThan(lastIdx);
      lastIdx = i;
    }
  });

  it('hashes meta separately so meta size does not bloat row_hash input', () => {
    const small = canonicalAuditText({
      id: 1,
      ts: '2026-04-30T00:00:00.000Z',
      event_type: 'e',
      meta: { x: 1 },
    });
    const big = canonicalAuditText({
      id: 1,
      ts: '2026-04-30T00:00:00.000Z',
      event_type: 'e',
      meta: { x: 'a'.repeat(100_000) },
    });
    // Same length: both contain a 64-char hex SHA-256 instead of the raw meta.
    expect(small.length).toBe(big.length);
  });

  it('null/missing fields are encoded as JSON null (matches Postgres jsonb_build_object)', () => {
    const text = canonicalAuditText({
      id: 2,
      ts: '2026-04-30T00:00:00.000Z',
      event_type: 'e',
    });
    expect(text).toMatch(/"account_id":null/);
    expect(text).toMatch(/"key_id":null/);
    expect(text).toMatch(/"endpoint":null/);
    expect(text).toMatch(/"status_class":null/);
    // meta absent => meta_hash is sha256("")
    expect(text).toContain(`"meta_hash":"${sha256Hex('')}"`);
  });
});

describe('computeRowHash + verifyChain', () => {
  it('chain of three rows verifies', () => {
    const rows = [
      { id: 1, ts: '2026-04-30T00:00:00.000Z', event_type: 'a' },
      { id: 2, ts: '2026-04-30T00:00:01.000Z', event_type: 'b' },
      { id: 3, ts: '2026-04-30T00:00:02.000Z', event_type: 'c' },
    ];
    let prev: Buffer = ZERO_HASH;
    const built = rows.map((r) => {
      const row_hash = computeRowHash(prev, r);
      const built = { ...r, prev_hash: prev, row_hash };
      prev = row_hash;
      return built;
    });
    expect(verifyChain(built)).toBe(-1);
  });

  it('detects tampering — flipping a byte in the middle row breaks the chain', () => {
    const rows = [
      { id: 1, ts: '2026-04-30T00:00:00.000Z', event_type: 'a' },
      { id: 2, ts: '2026-04-30T00:00:01.000Z', event_type: 'b' },
      { id: 3, ts: '2026-04-30T00:00:02.000Z', event_type: 'c' },
    ];
    let prev: Buffer = ZERO_HASH;
    const built = rows.map((r) => {
      const row_hash = computeRowHash(prev, r);
      const built = { ...r, prev_hash: prev, row_hash };
      prev = row_hash;
      return built;
    });

    // Tamper with row 2 (index 1) — change event_type without recomputing hashes.
    const tampered = built.map((r, i) =>
      i === 1 ? { ...r, event_type: 'evil' } : r,
    );
    expect(verifyChain(tampered)).toBe(1);
  });

  it('detects prev_hash linkage break', () => {
    const r1 = { id: 1, ts: '2026-04-30T00:00:00.000Z', event_type: 'a' };
    const row_hash_1 = computeRowHash(ZERO_HASH, r1);
    const r2 = { id: 2, ts: '2026-04-30T00:00:01.000Z', event_type: 'b' };
    // prev_hash on row 2 lies — claims a different chain ancestor
    const fake_prev = Buffer.alloc(32, 0xff);
    const row_hash_2 = computeRowHash(fake_prev, r2);
    const chain = [
      { ...r1, prev_hash: ZERO_HASH, row_hash: row_hash_1 },
      { ...r2, prev_hash: fake_prev, row_hash: row_hash_2 },
    ];
    expect(verifyChain(chain)).toBe(1);
  });
});
