/**
 * KMS adapter — authoritative custody for the API-key pepper and for
 * envelope-encrypting device-flow user codes.
 *
 * SPEC §6.1 (cryptographic primitives), §6.1.1 (HMAC + pepper rationale),
 * §6.1.2 (rotation: 90-day cadence, 7-day dual-pepper window).
 *
 * The lib never sees the raw pepper outside this module. Callers must:
 *   - getCurrentPepper() when issuing or rotating a key
 *   - getPepperByVersion(v) when validating an existing key
 *   - encryptDevice() / decryptDevice() for device-flow user codes
 *
 * Two impls live here:
 *   - AwsKmsAdapter: production. Uses GenerateDataKey for envelope.
 *   - InMemoryKmsAdapter: deterministic, used by unit + integration tests.
 *
 * Both are the same shape, so swapping them is a config change.
 */

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import {
  KMSClient,
  DecryptCommand,
  GenerateDataKeyCommand,
} from '@aws-sdk/client-kms';

/** Result of fetching a pepper. `data` is the raw 32-byte HMAC key. */
export interface PepperMaterial {
  readonly version: number;
  readonly data: Buffer;
}

export interface EncryptedBlob {
  /** Base64 of the KMS-encrypted data key (envelope). */
  readonly enc_data_key: string;
  /** Base64 of the AES-256-GCM ciphertext (auth tag appended). */
  readonly ciphertext: string;
  /** Base64 of the AES-256-GCM IV (12 bytes). */
  readonly iv: string;
}

export interface KmsAdapter {
  /** Pepper used for new key issuance. */
  getCurrentPepper(): Promise<PepperMaterial>;
  /** Pepper for an existing key's `key_pepper_version` column. */
  getPepperByVersion(version: number): Promise<PepperMaterial>;
  /** All currently-acceptable pepper versions (current + dual-window). */
  acceptedVersions(): Promise<ReadonlyArray<number>>;
  /** Envelope-encrypt arbitrary bytes (used for device-flow user codes). */
  encryptDevice(plaintext: Buffer): Promise<EncryptedBlob>;
  decryptDevice(blob: EncryptedBlob): Promise<Buffer>;
}

// ---------------------------------------------------------------------------
// AwsKmsAdapter
// ---------------------------------------------------------------------------

export interface AwsKmsAdapterConfig {
  /** KMS client (caller supplies for credential / region / mocks). */
  readonly client: KMSClient;
  /** KMS key alias for the pepper itself (used only by `pepperFetcher`). */
  readonly pepper_key_alias: string;
  /** KMS key alias for device-flow envelope encryption. */
  readonly device_key_alias: string;
  /** Resolves a pepper version to raw 32 bytes. Caller wraps a vault/SSM/etc. */
  readonly pepperFetcher: (version: number) => Promise<Buffer>;
  /** Latest pepper version. Bump on rotation. */
  readonly current_version: number;
  /** Versions accepted alongside current_version (dual-window). Empty after window. */
  readonly accepted_legacy_versions?: ReadonlyArray<number>;
}

export class AwsKmsAdapter implements KmsAdapter {
  constructor(private readonly cfg: AwsKmsAdapterConfig) {}

  async getCurrentPepper(): Promise<PepperMaterial> {
    return this.getPepperByVersion(this.cfg.current_version);
  }

  async getPepperByVersion(version: number): Promise<PepperMaterial> {
    const accepted = await this.acceptedVersions();
    if (!accepted.includes(version)) {
      throw new Error(`pepper_version_not_accepted: ${version}`);
    }
    const data = await this.cfg.pepperFetcher(version);
    if (data.length !== 32) {
      throw new Error('pepper_invalid_size: expected 32 bytes');
    }
    return { version, data };
  }

  async acceptedVersions(): Promise<ReadonlyArray<number>> {
    return [
      this.cfg.current_version,
      ...(this.cfg.accepted_legacy_versions ?? []),
    ];
  }

  async encryptDevice(plaintext: Buffer): Promise<EncryptedBlob> {
    const out = await this.cfg.client.send(
      new GenerateDataKeyCommand({
        KeyId: this.cfg.device_key_alias,
        KeySpec: 'AES_256',
      }),
    );
    if (!out.Plaintext || !out.CiphertextBlob) {
      throw new Error('kms_generate_data_key_returned_empty');
    }
    const dataKey = Buffer.from(out.Plaintext);
    const encDataKey = Buffer.from(out.CiphertextBlob);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      enc_data_key: encDataKey.toString('base64'),
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv: iv.toString('base64'),
    };
  }

  async decryptDevice(blob: EncryptedBlob): Promise<Buffer> {
    const out = await this.cfg.client.send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(blob.enc_data_key, 'base64'),
      }),
    );
    if (!out.Plaintext) throw new Error('kms_decrypt_returned_empty');
    const dataKey = Buffer.from(out.Plaintext);
    const iv = Buffer.from(blob.iv, 'base64');
    const ctAndTag = Buffer.from(blob.ciphertext, 'base64');
    if (ctAndTag.length < 16) throw new Error('ciphertext_too_short');
    const tag = ctAndTag.subarray(ctAndTag.length - 16);
    const ct = ctAndTag.subarray(0, ctAndTag.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', dataKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }
}

// ---------------------------------------------------------------------------
// InMemoryKmsAdapter (test-only)
// ---------------------------------------------------------------------------

/**
 * In-memory KMS for unit + integration tests. Deterministic, supports
 * version rotation. NOT FOR PRODUCTION USE — there is no key custody here.
 */
export class InMemoryKmsAdapter implements KmsAdapter {
  private peppers: Map<number, Buffer> = new Map();
  private currentVersion: number;
  private acceptedLegacy: Set<number> = new Set();
  private deviceKey: Buffer;

  constructor(opts?: {
    initial_version?: number;
    initial_pepper?: Buffer;
    device_key?: Buffer;
  }) {
    this.currentVersion = opts?.initial_version ?? 1;
    this.peppers.set(
      this.currentVersion,
      opts?.initial_pepper ?? randomBytes(32),
    );
    this.deviceKey = opts?.device_key ?? randomBytes(32);
  }

  /** Test helper: rotate to a new pepper, keeping the previous one accepted. */
  rotate(newPepper?: Buffer): { from: number; to: number } {
    const from = this.currentVersion;
    const to = from + 1;
    this.acceptedLegacy.add(from);
    this.peppers.set(to, newPepper ?? randomBytes(32));
    this.currentVersion = to;
    return { from, to };
  }

  /** Test helper: drop a legacy pepper version (simulate post-window cutover). */
  retire(version: number): void {
    this.acceptedLegacy.delete(version);
    // Keep the bytes around for audit replay (per §6.1.2).
  }

  async getCurrentPepper(): Promise<PepperMaterial> {
    return this.getPepperByVersion(this.currentVersion);
  }

  async getPepperByVersion(version: number): Promise<PepperMaterial> {
    const data = this.peppers.get(version);
    if (!data) throw new Error(`pepper_version_not_found: ${version}`);
    if (
      version !== this.currentVersion &&
      !this.acceptedLegacy.has(version)
    ) {
      throw new Error(`pepper_version_not_accepted: ${version}`);
    }
    return { version, data };
  }

  async acceptedVersions(): Promise<ReadonlyArray<number>> {
    return [this.currentVersion, ...this.acceptedLegacy.values()];
  }

  async encryptDevice(plaintext: Buffer): Promise<EncryptedBlob> {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.deviceKey, iv);
    const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      enc_data_key: 'inmemory',
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv: iv.toString('base64'),
    };
  }

  async decryptDevice(blob: EncryptedBlob): Promise<Buffer> {
    if (blob.enc_data_key !== 'inmemory') {
      throw new Error('inmemory_kms_data_key_mismatch');
    }
    const iv = Buffer.from(blob.iv, 'base64');
    const ctAndTag = Buffer.from(blob.ciphertext, 'base64');
    const tag = ctAndTag.subarray(ctAndTag.length - 16);
    const ct = ctAndTag.subarray(0, ctAndTag.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', this.deviceKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }
}
