import { describe, it, expect, beforeEach } from 'vitest';
import { mockClient } from 'aws-sdk-client-mock';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { AwsS3WormPutter } from '../../src/audit/worm-writer.js';

const s3Mock = mockClient(S3Client);

describe('AwsS3WormPutter (SPEC §6.4.2 / ADR-010)', () => {
  beforeEach(() => {
    s3Mock.reset();
  });

  it('forwards Bucket + Key + COMPLIANCE retention to PutObjectCommand', async () => {
    s3Mock.on(PutObjectCommand).resolves({});
    const putter = new AwsS3WormPutter({
      client: new S3Client({ region: 'us-east-1' }),
      bucket: 'audit-worm-bucket',
    });
    const retainUntil = new Date('2033-01-01T00:00:00Z');
    await putter.putObject({
      Key: 'audit/2026/04/30/42.json',
      Body: '{"hello":"world"}',
      ContentType: 'application/json',
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: 'alias/audit-encryption',
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: retainUntil,
    });
    const calls = s3Mock.commandCalls(PutObjectCommand);
    expect(calls.length).toBe(1);
    const input = calls[0]!.args[0].input;
    expect(input.Bucket).toBe('audit-worm-bucket');
    expect(input.Key).toBe('audit/2026/04/30/42.json');
    expect(input.ContentType).toBe('application/json');
    expect(input.ServerSideEncryption).toBe('aws:kms');
    expect(input.SSEKMSKeyId).toBe('alias/audit-encryption');
    expect(input.ObjectLockMode).toBe('COMPLIANCE');
    expect(input.ObjectLockRetainUntilDate).toEqual(retainUntil);
    expect(input.Body).toBe('{"hello":"world"}');
  });

  it('bubbles AWS errors so the outbox enqueue path runs', async () => {
    const err = new Error('AccessDenied');
    s3Mock.on(PutObjectCommand).rejects(err);
    const putter = new AwsS3WormPutter({
      client: new S3Client({ region: 'us-east-1' }),
      bucket: 'b',
    });
    await expect(
      putter.putObject({
        Key: 'k',
        Body: 'x',
        ContentType: 'application/json',
        ServerSideEncryption: 'aws:kms',
        SSEKMSKeyId: 'kms',
        ObjectLockMode: 'COMPLIANCE',
        ObjectLockRetainUntilDate: new Date(),
      }),
    ).rejects.toThrow(/AccessDenied/);
  });
});
