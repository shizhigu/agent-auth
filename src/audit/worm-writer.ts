/**
 * S3 Object Lock COMPLIANCE writer. SPEC §6.4.2 / ADR-010.
 *
 * Each audit event is mirrored to a separate AWS account + bucket with
 * `ObjectLockMode: COMPLIANCE` so it cannot be deleted/overwritten even
 * by the bucket's own root account during the retention window. This
 * blocks RT-12 (primary-DB compromise) and RT-28 (WORM suppression).
 *
 * Failure path: if PutObject fails (network, KMS, throttle), we enqueue
 * an `agent_audit_outbox` row keyed on the audit event id. The
 * `outbox-flusher` job retries until the WORM PutObject lands. The
 * outbox is also consulted by the §6.4.2 reconciliation to detect
 * audit-log entries that never reached WORM.
 */

import { ServiceUnavailableError } from '../errors.js';
import { defaultScrubber, type CompiledScrubber } from '../observability/scrubber.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';

export interface S3WormPut {
  readonly Key: string;
  readonly Body: string;
  readonly ContentType: string;
  readonly ServerSideEncryption: 'aws:kms';
  readonly SSEKMSKeyId: string;
  readonly ObjectLockMode: 'COMPLIANCE';
  readonly ObjectLockRetainUntilDate: Date;
}

/** Minimal interface so we don't pull @aws-sdk into unit tests. */
export interface WormPutter {
  putObject(input: S3WormPut): Promise<void>;
}

export interface AuditWormConfig {
  readonly bucket: string;
  readonly kms_key_id: string;
  readonly retention_years: number;
  readonly putter: WormPutter;
  readonly scrubber?: CompiledScrubber;
  /** Now for tests. */
  readonly now?: () => Date;
}

export interface AuditWormEvent {
  readonly id: string;
  readonly ts: Date | string;
  readonly event_type: string;
  readonly account_id?: string | null;
  readonly key_id?: string | null;
  readonly endpoint?: string | null;
  readonly status_class?: number | null;
  readonly meta?: Record<string, unknown> | null;
  readonly row_hash: string; // hex
  readonly prev_hash: string; // hex
  /**
   * §6.4.2 / RT-28: when a Tier B event hits the outbox (i.e., the WORM
   * put failed), the caller must fail-closed with 503 audit_unavailable
   * so an attacker who suppresses S3 cannot get a free pass to revoke /
   * rotate / suspend without a durable WORM record. Tier A is best-effort.
   * Default: 'A'.
   */
  readonly tier?: 'A' | 'B';
}

export async function writeAuditToWorm(
  pg: PostgresAdapter,
  cfg: AuditWormConfig,
  event: AuditWormEvent,
): Promise<{ status: 'ok' | 'outboxed'; key: string; error?: string }> {
  const scrubber = cfg.scrubber ?? defaultScrubber;
  const ts =
    typeof event.ts === 'string' ? new Date(event.ts) : event.ts;
  const key = `audit/${dateShard(ts)}/${event.id}.json`;
  const safeMeta =
    event.meta && typeof event.meta === 'object'
      ? scrubber.scrub(event.meta)
      : null;
  const body: AuditWormBody = {
    id: event.id,
    ts: ts.toISOString(),
    event_type: event.event_type,
    account_id: event.account_id ?? null,
    key_id: event.key_id ?? null,
    endpoint: event.endpoint ?? null,
    status_class: event.status_class ?? null,
    meta: safeMeta as Record<string, unknown> | null,
    row_hash: event.row_hash,
    prev_hash: event.prev_hash,
  };
  const bodyJson = JSON.stringify(body);
  const retainUntil = addYears(cfg.now ? cfg.now() : new Date(), cfg.retention_years);
  try {
    await cfg.putter.putObject({
      Key: key,
      Body: bodyJson,
      ContentType: 'application/json',
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: cfg.kms_key_id,
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: retainUntil,
    });
    return { status: 'ok', key };
  } catch (err) {
    const error_msg = errorMessage(err);
    await pg
      .query(
        `INSERT INTO agent_audit_outbox (event_id, payload, attempts, last_error)
         VALUES ($1::bigint, $2::jsonb, 0, $3)`,
        [event.id, bodyJson, error_msg.slice(0, 500)],
      )
      .catch(() => undefined);
    // §6.4.2 / RT-28: Tier B events MUST fail-closed when they cannot reach
    // WORM. The outbox row stays for retry — but the caller is told the
    // operation is not durably audited so it can return 503 to the client
    // and avoid silent suppression of revoke/rotate evidence.
    if (event.tier === 'B') {
      throw new ServiceUnavailableError(
        'audit_unavailable',
        `worm_put_failed: ${error_msg}`,
      );
    }
    return { status: 'outboxed', key, error: error_msg };
  }
}

interface AuditWormBody {
  id: string;
  ts: string;
  event_type: string;
  account_id: string | null;
  key_id: string | null;
  endpoint: string | null;
  status_class: number | null;
  meta: Record<string, unknown> | null;
  row_hash: string;
  prev_hash: string;
}

function dateShard(ts: Date): string {
  // YYYY/MM/DD partition keys keep S3 listings tractable.
  const y = ts.getUTCFullYear();
  const m = String(ts.getUTCMonth() + 1).padStart(2, '0');
  const d = String(ts.getUTCDate()).padStart(2, '0');
  return `${y}/${m}/${d}`;
}

function addYears(date: Date, years: number): Date {
  const out = new Date(date);
  out.setUTCFullYear(out.getUTCFullYear() + years);
  return out;
}

function errorMessage(err: unknown): string {
  if (err && typeof err === 'object' && 'message' in err) {
    const m = (err as { message: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return 'unknown_error';
}

// ---------------------------------------------------------------------------
// AwsS3WormPutter — production binding to @aws-sdk/client-s3.
// Constructed by SaaS app config; the lib stays framework-decoupled.
// ---------------------------------------------------------------------------

import {
  S3Client,
  PutObjectCommand,
  type ServerSideEncryption,
  type ObjectLockMode,
} from '@aws-sdk/client-s3';

export interface AwsS3WormPutterConfig {
  readonly client: S3Client;
  readonly bucket: string;
}

export class AwsS3WormPutter implements WormPutter {
  constructor(private readonly cfg: AwsS3WormPutterConfig) {}
  async putObject(input: S3WormPut): Promise<void> {
    await this.cfg.client.send(
      new PutObjectCommand({
        Bucket: this.cfg.bucket,
        Key: input.Key,
        Body: input.Body,
        ContentType: input.ContentType,
        ServerSideEncryption: input.ServerSideEncryption as ServerSideEncryption,
        SSEKMSKeyId: input.SSEKMSKeyId,
        ObjectLockMode: input.ObjectLockMode as ObjectLockMode,
        ObjectLockRetainUntilDate: input.ObjectLockRetainUntilDate,
      }),
    );
  }
}

// ---------------------------------------------------------------------------
// In-memory test putter that records calls.
// ---------------------------------------------------------------------------

export class InMemoryWormPutter implements WormPutter {
  readonly puts: S3WormPut[] = [];
  shouldFailNext = 0;
  async putObject(input: S3WormPut): Promise<void> {
    if (this.shouldFailNext > 0) {
      this.shouldFailNext--;
      throw new Error('inmemory_worm_failure');
    }
    this.puts.push(input);
  }
}
