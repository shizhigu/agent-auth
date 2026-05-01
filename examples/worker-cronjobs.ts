/**
 * agent-auth — background worker example.
 *
 * Run this as a SEPARATE process from the API one (per SPEC §13.1.2).
 * A single replica is enough; the lib's jobs use FOR UPDATE SKIP
 * LOCKED so two workers running concurrently is also safe.
 *
 * The cron schedules below match the SPEC §13.1.2 cadence:
 *   - registration-session reaper:  every minute
 *   - audit outbox flusher:         continuous (we use 30 s here)
 *   - audit hash-chain verifier:    hourly
 *   - audit partition manager:      daily
 *   - rotation-grace expirer:       every 60 s
 *   - webhook replay polling:       every 5 min
 *   - idempotency reconciliation:   every 60 s
 *   - agent_jobs worker:            every 5 s (lease-recoverable)
 *   - expired-rows reaper:          every minute
 *   - Redis SET reconciliation:     hourly
 *
 * The scheduling library shown here is a tiny in-process timer wheel.
 * Production SaaSes typically swap in BullMQ / Temporal / a proper
 * cron pod — the IMPORTANT bit is calling the lib's job functions
 * with the right deps, not how the timer fires.
 */

import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { KMSClient } from '@aws-sdk/client-kms';
import { S3Client } from '@aws-sdk/client-s3';

import {
  reapRegistrationSessions,
  flushAuditOutbox,
  verifyAuditChain,
  manageAuditPartitions,
  expireRotationGrace,
  runWebhookReplay,
  reconcileUnknownIdempotency,
  processAgentJobs,
  reapExpiredRows,
  reconcileAccountKeySets,
  PostgresAdapter,
  IoredisAdapter,
  AwsKmsAdapter,
  AwsS3WormPutter,
} from '@vouch/server';

// ----- 1. Adapters (same as the API process) -----------------------------

const pgPool = new Pool({ connectionString: process.env.DATABASE_URL });
const pg = new PostgresAdapter({ pool: { connectionString: process.env.DATABASE_URL } });

const redisClient = new Redis(process.env.REDIS_URL!);
const redisSubscriber = new Redis(process.env.REDIS_URL!);
const redis = new IoredisAdapter({ client: redisClient, subscriber: redisSubscriber });
await redis.loadScripts();

const kms = new AwsKmsAdapter({
  client: new KMSClient({ region: process.env.AWS_REGION ?? 'us-east-1' }),
  pepper_key_alias: process.env.KMS_PEPPER_ALIAS!,
  device_key_alias: process.env.KMS_DEVICE_ALIAS!,
  pepperFetcher: async (_v) => {
    /* SaaS wires this to its secret manager */
    return Buffer.alloc(32);
  },
  current_version: 1,
});

const wormPutter = new AwsS3WormPutter({
  client: new S3Client({ region: process.env.AWS_REGION ?? 'us-east-1' }),
  bucket: process.env.AUDIT_WORM_BUCKET!,
});

// ----- 2. Tiny timer wheel ------------------------------------------------

interface ScheduledTask {
  name: string;
  intervalMs: number;
  fn: () => Promise<void>;
}

function schedule(tasks: ReadonlyArray<ScheduledTask>): void {
  for (const t of tasks) {
    const tick = async () => {
      try {
        await t.fn();
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[${t.name}] tick failed`, err);
      } finally {
        setTimeout(tick, t.intervalMs).unref();
      }
    };
    // Stagger initial delays so all tasks don't fire at startup at once.
    setTimeout(tick, Math.random() * t.intervalMs).unref();
  }
}

// ----- 3. Tasks -----------------------------------------------------------

schedule([
  {
    name: 'reaper:registration-sessions',
    intervalMs: 60_000,
    fn: async () => { await reapRegistrationSessions(pg); },
  },
  {
    name: 'reaper:expired-rows',
    intervalMs: 60_000,
    fn: async () => {
      await reapExpiredRows({ postgres: pg });
    },
  },
  {
    name: 'audit:outbox-flusher',
    intervalMs: 30_000,
    fn: async () => {
      await flushAuditOutbox({
        postgres: pg,
        putter: wormPutter,
        cfg: {
          kms_key_id: process.env.AUDIT_WORM_KMS_KEY_ID!,
          retention_years: 7,
        },
      });
    },
  },
  {
    name: 'audit:hash-chain-verifier',
    intervalMs: 60 * 60_000,
    fn: async () => {
      const out = await verifyAuditChain({ postgres: pg });
      if (out.first_break_index >= 0) {
        // eslint-disable-next-line no-console
        console.error('audit chain break at', out.first_break_id);
      }
    },
  },
  {
    name: 'audit:partition-manager',
    intervalMs: 24 * 60 * 60_000,
    fn: async () => {
      // The migrator role owns partitions; in production this would use
      // a separate adapter. Shown here at the boot pool for brevity.
      const migrator = new PostgresAdapter({
        pool: { connectionString: process.env.DATABASE_URL },
        role: 'agent_auth_migrator',
      });
      try {
        await manageAuditPartitions({ postgres: migrator, lookahead_days: 7 });
      } finally {
        await migrator.close();
      }
    },
  },
  {
    name: 'rotation:grace-expirer',
    intervalMs: 60_000,
    fn: async () => {
      await expireRotationGrace({ postgres: pg });
    },
  },
  {
    name: 'webhook:replay',
    intervalMs: 5 * 60_000,
    fn: async () => {
      await runWebhookReplay({
        postgres: pg,
        // SaaS wires the App-JWT builder for /app/hook/deliveries.
        buildAppJwt: async () => 'replace-with-app-jwt',
      });
    },
  },
  {
    name: 'idempotency:reconciler',
    intervalMs: 60_000,
    fn: async () => {
      await reconcileUnknownIdempotency({
        postgres: pg,
        // SaaS implements this — given (operation_type, resource_ref),
        // looks at the actual resource state and returns
        // {kind:'committed'|'not_found'|'indeterminate', ...}.
        checkResourceState: async (_op, _ref) => ({ kind: 'indeterminate' }),
      });
    },
  },
  {
    name: 'agent_jobs:worker',
    intervalMs: 5_000,
    fn: async () => {
      await processAgentJobs({ postgres: pg, redis });
    },
  },
  {
    name: 'redis:reconcile-account-key-sets',
    intervalMs: 60 * 60_000,
    fn: async () => {
      await reconcileAccountKeySets({ postgres: pg, redis });
    },
  },
]);

// ----- 4. Graceful shutdown ----------------------------------------------

async function shutdown() {
  await pg.close().catch(() => undefined);
  await redis.close?.().catch(() => undefined);
  await pgPool.end().catch(() => undefined);
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Suppress unused-export warning for the kms binding (left in scope so
// the example imports still compile when SaaSes copy this file).
void kms;

// eslint-disable-next-line no-console
console.log('agent-auth worker started');
