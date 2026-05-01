/**
 * Integration test fixtures. Boots a real Postgres + Redis via testcontainers,
 * runs the schema migrations from `schema/migrations/`, and exposes a typed
 * fixture object the test files share.
 *
 * Each suite calls `await provisionFixture()` in its `beforeAll`. The
 * containers are reused across tests in a single fork (vitest config sets
 * `singleFork: true` for the integration tier).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  PostgreSqlContainer,
  type StartedPostgreSqlContainer,
} from '@testcontainers/postgresql';
import { RedisContainer, type StartedRedisContainer } from '@testcontainers/redis';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import {
  IoredisAdapter,
  KEY_REVOCATION_EPOCH,
} from '../../src/storage/redis-adapter.js';
import { Redis } from 'ioredis';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import type { ResolvedConfig } from '../../src/config.js';
import type { IdentityProvider } from '../../src/types.js';
import { LocalCache } from '../../src/cache/local-cache.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = join(__dirname, '..', '..', 'schema', 'migrations');

export interface IntegrationFixture {
  readonly pg_container: StartedPostgreSqlContainer;
  readonly redis_container: StartedRedisContainer;
  readonly postgres: PostgresAdapter;
  readonly redis: IoredisAdapter;
  readonly redis_client: Redis;
  readonly redis_subscriber: Redis;
  readonly kms: InMemoryKmsAdapter;
  readonly resolved: ResolvedConfig;
  cleanup(): Promise<void>;
}

class StubProvider implements IdentityProvider {
  readonly name = 'github_app';
  async beginRegistration() {
    return {};
  }
  async exchangeOrVerify(): Promise<never> {
    throw new Error('not used in integration setup');
  }
  async revalidate() {
    return { still_valid: true };
  }
}

export async function provisionFixture(): Promise<IntegrationFixture> {
  const pg_container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('agent_auth')
    .withUsername('agent_auth_app_user')
    .withPassword('test_pw')
    .start();

  const redis_container = await new RedisContainer('redis:7-alpine').start();

  // The migrations grant to the agent_auth_* roles which the connecting user
  // doesn't yet inherit. Connect first as the boot superuser to:
  //   1. apply migrations as superuser
  //   2. GRANT all the agent_auth_app role to the test user
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

  // Apply migrations using a superuser session (no SET ROLE so DDL works).
  const bootClient = await adminAdapter['pool'].connect();
  try {
    for (const f of readdirSync(MIGRATIONS_DIR).sort()) {
      if (!f.endsWith('.sql') || f.endsWith('.down.sql')) continue;
      const sql = readFileSync(join(MIGRATIONS_DIR, f), 'utf8');
      await bootClient.query(sql);
    }
    // The boot user is the ROLE the test connects as. The migrations
    // already CREATE ROLE agent_auth_app NOLOGIN; let the boot user inherit
    // its privileges so SET ROLE works in our adapter.
    await bootClient.query(
      `GRANT agent_auth_app TO ${pg_container.getUsername()};
       GRANT agent_auth_admin TO ${pg_container.getUsername()};
       GRANT agent_auth_migrator TO ${pg_container.getUsername()};`,
    );
  } finally {
    bootClient.release();
  }
  await adminAdapter.close();

  const postgres = new PostgresAdapter({
    pool: {
      host: pg_container.getHost(),
      port: pg_container.getPort(),
      database: pg_container.getDatabase(),
      user: pg_container.getUsername(),
      password: pg_container.getPassword(),
    },
    role: 'agent_auth_app',
  });

  const redisUrl = redis_container.getConnectionUrl();
  const redis_client = new Redis(redisUrl);
  const redis_subscriber = new Redis(redisUrl);
  const redis = new IoredisAdapter({ client: redis_client, subscriber: redis_subscriber });
  await redis.loadScripts();
  // Ensure clean state.
  await redis_client.flushdb();
  await redis_client.set(KEY_REVOCATION_EPOCH, '0');

  const kms = new InMemoryKmsAdapter();

  const resolved: ResolvedConfig = {
    internal_secret: Buffer.alloc(32, 0xa5),
    identity_providers: [new StubProvider()],
    storage: { postgres, redis, kms },
    validation: {
      mode: 'strict_uncached',
      local_cache_capacity: 1000,
      local_cache_ttl_ms: 30_000,
      redis_cache_ttl_seconds: 30,
    },
    observability: { metric_prefix: 'agent_auth_test', service_name: 'agent-auth-int' },
  };

  return {
    pg_container,
    redis_container,
    postgres,
    redis,
    redis_client,
    redis_subscriber,
    kms,
    resolved,
    async cleanup() {
      await postgres.close().catch(() => undefined);
      await redis.close?.().catch(() => undefined);
      await pg_container.stop().catch(() => undefined);
      await redis_container.stop().catch(() => undefined);
    },
  };
}

export function makeLocalCache(): LocalCache {
  return new LocalCache({ capacity: 1000, ttl_ms: 30_000 });
}
