/**
 * Chaos: simulate Redis partition. SPEC §12.4 / RT-3 / RT-25 / RT-26.
 *
 * Strategy: stop the Redis container mid-flight so the next Redis call fails.
 * Confirm validateKey still rejects bad secrets (no false accept) and that
 * a healthy validation against the same key/secret pre-partition still
 * succeeded.
 *
 * Postgres remains the authoritative store at all times — Redis is only
 * acceleration. The lib's contract is: a Redis outage degrades cache hit
 * rate but never causes false acceptance / false rejection.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import {
  RedisContainer,
  type StartedRedisContainer,
} from '@testcontainers/redis';
import { Redis } from 'ioredis';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import { IoredisAdapter } from '../../src/storage/redis-adapter.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { validateKey } from '../../src/middleware/validate-key.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, '..', '..', 'schema', 'migrations');

describe('chaos: Redis partition (SPEC §12.4 / RT-25)', () => {
  let pg_container: StartedPostgreSqlContainer;
  let redis_container: StartedRedisContainer;
  let postgres: PostgresAdapter;
  let redis_client: Redis;
  let redis_subscriber: Redis;
  let redis: IoredisAdapter;
  let kms: InMemoryKmsAdapter;
  let bearer: string;
  let bearer_bad: string;

  beforeAll(async () => {
    pg_container = await new PostgreSqlContainer('postgres:16-alpine')
      .withDatabase('agent_auth')
      .withUsername('agent_auth_app_user')
      .withPassword('test_pw')
      .start();
    redis_container = await new RedisContainer('redis:7-alpine').start();

    redis_client = new Redis(redis_container.getConnectionUrl(), {
      maxRetriesPerRequest: 1,
    });
    redis_subscriber = new Redis(redis_container.getConnectionUrl(), {
      maxRetriesPerRequest: 1,
    });
    // Silence ioredis 'unhandled error' on disconnect.
    redis_client.on('error', () => undefined);
    redis_subscriber.on('error', () => undefined);
    redis = new IoredisAdapter({ client: redis_client, subscriber: redis_subscriber });
    await redis.loadScripts();

    const adminAdapter = new PostgresAdapter({
      pool: {
        host: pg_container.getHost(),
        port: pg_container.getPort(),
        database: pg_container.getDatabase(),
        user: pg_container.getUsername(),
        password: pg_container.getPassword(),
      },
      role: 'agent_auth_migrator',
    });
    const bootClient = await adminAdapter['pool'].connect();
    try {
      for (const f of readdirSync(MIGRATIONS_DIR).sort()) {
        if (!f.endsWith('.sql') || f.endsWith('.down.sql')) continue;
        await bootClient.query(readFileSync(join(MIGRATIONS_DIR, f), 'utf8'));
      }
      await bootClient.query(
        `GRANT agent_auth_app TO ${pg_container.getUsername()};`,
      );
    } finally {
      bootClient.release();
    }
    await adminAdapter.close();

    postgres = new PostgresAdapter({
      pool: {
        host: pg_container.getHost(),
        port: pg_container.getPort(),
        database: pg_container.getDatabase(),
        user: pg_container.getUsername(),
        password: pg_container.getPassword(),
      },
      role: 'agent_auth_app',
    });
    kms = new InMemoryKmsAdapter();

    const acc = await postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('chaos-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', '11111', 'Iv1.c', 'github.com', 'medium',
                 'chaos-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const secret = randomBytes(32);
    const pepper = await kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const key_id = `agk_${randomBytes(6).toString('base64url')}`;
    await postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;
    bearer_bad = `${key_id}.${randomBytes(32).toString('base64url')}`;
  }, 240_000);

  afterAll(async () => {
    await postgres?.close().catch(() => undefined);
    redis_client?.disconnect();
    redis_subscriber?.disconnect();
    await pg_container?.stop().catch(() => undefined);
    await redis_container?.stop().catch(() => undefined);
  }, 120_000);

  function deps() {
    return {
      postgres,
      redis,
      kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
    };
  }

  it('healthy Redis: validateKey returns AgentContext (RT-25 control)', async () => {
    const ctx = await validateKey(bearer, deps());
    expect(ctx.identity.provider).toBe('github_app');
  });

  it('partitioned Redis: validateKey degrades safely — no false acceptance', async () => {
    // Stop Redis to simulate a complete partition. ioredis errors on the
    // next epoch read.
    await redis_container.stop();

    // Invariant: with a bad secret, validateKey MUST NOT return a successful
    // AgentContext. Acceptable outcomes:
    //   a. AgentAuthError(401, 'invalid_secret') — Redis read returned
    //      something usable (e.g. lazy reconnect succeeded against the
    //      stopped container's tcp RST), Postgres lookup hit, HMAC failed.
    //   b. Raw Redis connection error — Redis unreachable; lib bubbles up.
    //   c. ServiceUnavailableError(5xx) — explicit fail-closed.
    // Forbidden: a return value that looks like an AgentContext.
    let outcome: 'threw' | 'returned' = 'threw';
    let returned: unknown;
    let thrown: unknown;
    try {
      returned = await validateKey(bearer_bad, deps());
      outcome = 'returned';
    } catch (err) {
      thrown = err;
    }
    if (outcome === 'returned') {
      // Should never happen — chaos invariant violated.
      expect(returned).toBeUndefined();
    }
    // Whatever was thrown, it's an Error or AgentAuthError, never a
    // successful AgentContext shape.
    expect(thrown).toBeDefined();
    const err = thrown as { status?: number; code?: string; message?: string };
    if (err.status !== undefined) {
      expect(err.status).toBeGreaterThanOrEqual(401);
    } else {
      // Raw Redis error has a message but no status.
      expect(typeof err.message).toBe('string');
    }
  });
});
