import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import {
  KMSClient,
  GenerateDataKeyCommand,
  DecryptCommand,
} from '@aws-sdk/client-kms';
import { AwsKmsAdapter } from '../../src/storage/kms-adapter.js';
import { randomBytes, createCipheriv } from 'node:crypto';

const kmsMock = mockClient(KMSClient);

describe('AwsKmsAdapter (SPEC §6.1.1 / §6.1.2)', () => {
  beforeEach(() => {
    kmsMock.reset();
  });

  it('getCurrentPepper / getPepperByVersion returns 32-byte material', async () => {
    const pepperBytes = Buffer.alloc(32, 0x42);
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'alias/agent-auth-pepper',
      device_key_alias: 'alias/agent-auth-device',
      current_version: 7,
      pepperFetcher: async (v) => {
        expect(v).toBe(7);
        return pepperBytes;
      },
    });
    const cur = await adapter.getCurrentPepper();
    expect(cur.version).toBe(7);
    expect(cur.data.length).toBe(32);
    expect(cur.data.equals(pepperBytes)).toBe(true);
  });

  it('rejects pepper bytes that are not 32 bytes', async () => {
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'b',
      current_version: 1,
      pepperFetcher: async () => Buffer.alloc(31),
    });
    await expect(adapter.getCurrentPepper()).rejects.toThrow(/invalid_size/);
  });

  it('acceptedVersions includes legacy versions during dual-window rotation', async () => {
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'b',
      current_version: 3,
      accepted_legacy_versions: [2, 1],
      pepperFetcher: async () => Buffer.alloc(32),
    });
    const versions = await adapter.acceptedVersions();
    expect(new Set(versions)).toEqual(new Set([1, 2, 3]));
  });

  it('refuses pepper version not in accepted set', async () => {
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'b',
      current_version: 5,
      pepperFetcher: async () => Buffer.alloc(32),
    });
    await expect(adapter.getPepperByVersion(99)).rejects.toThrow(/not_accepted/);
  });

  it('encryptDevice uses GenerateDataKey + AES-256-GCM, decryptDevice round-trips', async () => {
    // Stable test "data key" so encrypt + decrypt produce a known shape.
    const dataKey = Buffer.alloc(32, 0xab);
    const cipherTextBlob = Buffer.from('FAKE_CIPHERTEXT_BLOB');

    kmsMock.on(GenerateDataKeyCommand).resolves({
      Plaintext: dataKey,
      CiphertextBlob: cipherTextBlob,
    });
    kmsMock.on(DecryptCommand).callsFake(async (input) => {
      // Verify the adapter sent the same blob it got back from GenerateDataKey.
      const got = Buffer.from(input.CiphertextBlob as Uint8Array);
      expect(got.equals(cipherTextBlob)).toBe(true);
      return { Plaintext: dataKey };
    });

    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'alias/device',
      current_version: 1,
      pepperFetcher: async () => Buffer.alloc(32),
    });

    const plaintext = Buffer.from('user-code-WDJB-MJHT', 'utf8');
    const blob = await adapter.encryptDevice(plaintext);
    expect(blob.enc_data_key).toBe(cipherTextBlob.toString('base64'));
    // IV is 12 bytes for GCM.
    expect(Buffer.from(blob.iv, 'base64').length).toBe(12);
    // Ciphertext is plaintext_len + 16-byte auth tag.
    const ctAndTag = Buffer.from(blob.ciphertext, 'base64');
    expect(ctAndTag.length).toBe(plaintext.length + 16);

    const back = await adapter.decryptDevice(blob);
    expect(back.equals(plaintext)).toBe(true);
  });

  it('throws on truncated ciphertext (< 16-byte tag)', async () => {
    const dataKey = Buffer.alloc(32, 1);
    kmsMock.on(GenerateDataKeyCommand).resolves({ Plaintext: dataKey, CiphertextBlob: Buffer.from('x') });
    kmsMock.on(DecryptCommand).resolves({ Plaintext: dataKey });
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'b',
      current_version: 1,
      pepperFetcher: async () => Buffer.alloc(32),
    });
    await expect(
      adapter.decryptDevice({ enc_data_key: 'x', ciphertext: Buffer.alloc(8).toString('base64'), iv: Buffer.alloc(12).toString('base64') }),
    ).rejects.toThrow(/ciphertext_too_short/);
  });

  it('throws when KMS returns no Plaintext on GenerateDataKey', async () => {
    kmsMock.on(GenerateDataKeyCommand).resolves({});
    const adapter = new AwsKmsAdapter({
      client: new KMSClient({ region: 'us-east-1' }),
      pepper_key_alias: 'a',
      device_key_alias: 'b',
      current_version: 1,
      pepperFetcher: async () => Buffer.alloc(32),
    });
    await expect(adapter.encryptDevice(Buffer.from('x'))).rejects.toThrow(/returned_empty/);
  });

  it('proxies envelope details — ciphertext authenticated by GCM tag (helper sanity)', () => {
    // Sanity: prove the GCM tag scheme we expect AwsKmsAdapter to use.
    const key = Buffer.alloc(32, 9);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([c.update(Buffer.from('hi')), c.final()]);
    const tag = c.getAuthTag();
    expect(tag.length).toBe(16);
    expect(enc.length + tag.length).toBe(2 + 16);
  });
});
