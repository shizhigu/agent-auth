import { describe, it, expect, beforeAll } from 'vitest';
import {
  sealedBoxReady,
  seal,
  open,
  keypair,
  SEALED_BOX_OVERHEAD,
} from '../../src/crypto/sealed-box.js';

describe('sealed-box (SPEC §2.6 / ADR-004)', () => {
  beforeAll(async () => {
    await sealedBoxReady();
  });

  it('round-trips an arbitrary plaintext', () => {
    const kp = keypair();
    const pt = Buffer.from(JSON.stringify({ key: 'agk_x.secret', is_first_key: true }));
    const ct = seal(pt, kp.publicKey);
    const back = open(ct, kp.publicKey, kp.secretKey);
    expect(back.toString('utf8')).toBe(pt.toString('utf8'));
  });

  it('overhead is exactly 48 bytes (32 ephemeral pubkey + 16 MAC)', () => {
    const kp = keypair();
    const pt = Buffer.from('a'.repeat(100));
    const ct = seal(pt, kp.publicKey);
    expect(ct.length - pt.length).toBe(SEALED_BOX_OVERHEAD);
  });

  it('decrypting with the wrong secret fails', () => {
    const a = keypair();
    const b = keypair();
    const ct = seal(Buffer.from('hello'), a.publicKey);
    expect(() => open(ct, b.publicKey, b.secretKey)).toThrow();
  });

  it('rejects pubkey of wrong length (RT-20 mitigations: pubkey size enforced)', () => {
    expect(() => seal(Buffer.from('x'), Buffer.alloc(31))).toThrow();
    expect(() => seal(Buffer.from('x'), Buffer.alloc(33))).toThrow();
  });
});
