import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  hmacWithPepper,
  constantTimeEqualBuffers,
  hashNewKey,
  verifyKey,
} from '../../src/crypto/hmac-pepper.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';

describe('hmacWithPepper (SPEC §6.1.1)', () => {
  it('produces 32 bytes', () => {
    const out = hmacWithPepper(Buffer.alloc(32), 'hello');
    expect(out.length).toBe(32);
  });

  it('is deterministic for the same pepper and secret', () => {
    const pepper = Buffer.alloc(32, 7);
    expect(hmacWithPepper(pepper, 'x').equals(hmacWithPepper(pepper, 'x'))).toBe(true);
  });

  it('changes when the secret changes', () => {
    const pepper = Buffer.alloc(32, 7);
    expect(hmacWithPepper(pepper, 'a').equals(hmacWithPepper(pepper, 'b'))).toBe(false);
  });

  it('changes when the pepper changes', () => {
    const a = Buffer.alloc(32, 1);
    const b = Buffer.alloc(32, 2);
    expect(hmacWithPepper(a, 'x').equals(hmacWithPepper(b, 'x'))).toBe(false);
  });
});

describe('constantTimeEqualBuffers', () => {
  it('returns false for different lengths without throwing', () => {
    expect(constantTimeEqualBuffers(Buffer.from([1, 2]), Buffer.from([1, 2, 3]))).toBe(false);
  });

  it('returns true for equal buffers', () => {
    const a = Buffer.from('abcd');
    const b = Buffer.from('abcd');
    expect(constantTimeEqualBuffers(a, b)).toBe(true);
  });

  it('returns false for differing buffers of equal length', () => {
    expect(constantTimeEqualBuffers(Buffer.from('abcd'), Buffer.from('abce'))).toBe(false);
  });
});

describe('hashNewKey + verifyKey (round-trip)', () => {
  it('verifies a freshly issued key', async () => {
    const kms = new InMemoryKmsAdapter();
    const secret = randomBytes(32);
    const { key_hash, key_pepper_version } = await hashNewKey(secret, kms);
    const result = await verifyKey(secret, key_hash, key_pepper_version, kms);
    expect(result).toEqual({ matched: true, pepper_version: 1 });
  });

  it('rejects a wrong secret', async () => {
    const kms = new InMemoryKmsAdapter();
    const secret = randomBytes(32);
    const { key_hash, key_pepper_version } = await hashNewKey(secret, kms);
    const result = await verifyKey(randomBytes(32), key_hash, key_pepper_version, kms);
    expect(result.matched).toBe(false);
  });
});

describe('verifyKey under dual-pepper rotation window (§6.1.2)', () => {
  it('still verifies a key issued with v1 after rotating to v2', async () => {
    const kms = new InMemoryKmsAdapter();
    const secret = randomBytes(32);

    // Issue a key under v1
    const { key_hash, key_pepper_version } = await hashNewKey(secret, kms);
    expect(key_pepper_version).toBe(1);

    // Rotate to v2; v1 stays in the dual window
    const { from, to } = kms.rotate();
    expect(from).toBe(1);
    expect(to).toBe(2);

    // Old key still validates AND we know which version matched (v1)
    const result = await verifyKey(secret, key_hash, key_pepper_version, kms);
    expect(result).toEqual({ matched: true, pepper_version: 1 });
  });

  it('reports the new version when a key is re-issued post-rotation', async () => {
    const kms = new InMemoryKmsAdapter();
    kms.rotate(); // v1 -> v2 before any keys exist
    const secret = randomBytes(32);
    const { key_hash, key_pepper_version } = await hashNewKey(secret, kms);
    expect(key_pepper_version).toBe(2);
    const result = await verifyKey(secret, key_hash, key_pepper_version, kms);
    expect(result).toEqual({ matched: true, pepper_version: 2 });
  });

  it('fails verification once an old pepper version is retired', async () => {
    const kms = new InMemoryKmsAdapter();
    const secret = randomBytes(32);
    const { key_hash, key_pepper_version } = await hashNewKey(secret, kms);

    kms.rotate();    // v1 still accepted
    kms.retire(1);   // v1 no longer accepted

    const result = await verifyKey(secret, key_hash, key_pepper_version, kms);
    expect(result.matched).toBe(false);
  });
});

describe('InMemoryKmsAdapter envelope round-trip', () => {
  it('encrypt then decrypt yields original plaintext', async () => {
    const kms = new InMemoryKmsAdapter();
    const data = Buffer.from('user-code-ABCD-1234', 'utf8');
    const blob = await kms.encryptDevice(data);
    const back = await kms.decryptDevice(blob);
    expect(back.equals(data)).toBe(true);
  });

  it('rejects ciphertext from a different adapter instance', async () => {
    const a = new InMemoryKmsAdapter();
    const b = new InMemoryKmsAdapter();
    const blob = await a.encryptDevice(Buffer.from('x'));
    // Different instances have different deviceKey -> auth tag mismatch
    await expect(b.decryptDevice(blob)).rejects.toThrow();
  });

  it('acceptedVersions reflects rotation history', async () => {
    const kms = new InMemoryKmsAdapter();
    expect(await kms.acceptedVersions()).toEqual([1]);
    kms.rotate();
    expect(new Set(await kms.acceptedVersions())).toEqual(new Set([1, 2]));
    kms.retire(1);
    expect(await kms.acceptedVersions()).toEqual([2]);
  });
});
