/**
 * agent-auth — Express integration example.
 *
 * Demonstrates the canonical setup with the real lib API (per SPEC §11.4
 * AgentAuthConfig and §6.3 confused-deputy prevention).
 *
 * 5 minutes from `npm install @vouch/server express @aws-sdk/client-kms pg ioredis`
 * to a SaaS that can validate agent-issued bearer tokens.
 */

import express from 'express';
import type { Request } from 'express';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { KMSClient } from '@aws-sdk/client-kms';

import {
  resolveConfig,
  expressMiddleware,
  makeValidateKeyDeps,
  PostgresAdapter,
  IoredisAdapter,
  AwsKmsAdapter,
  type AgentContext,
} from '@vouch/server';
// Optional: example only — your SaaS plugs its own GitHub App provider.
import { GitHubAppProvider } from '@vouch/server/identity/github-app/browser-flow.js';

// ----- Type augmentation (exactly once in your codebase) -------------------
declare module 'express' {
  interface Request {
    agent?: AgentContext;
  }
  // NOTE: we do NOT extend req.user. Per SPEC §6.3, agent-auth lives in
  // req.agent so it cannot be confused with whatever your human-auth lib
  // already attached to req.user.
}

// ----- 1. Build adapters --------------------------------------------------
const pg = new PostgresAdapter({
  pool: { connectionString: process.env.DATABASE_URL! },
  role: 'agent_auth_app',
});

const redisClient = new Redis(process.env.REDIS_URL!);
const redisSub = new Redis(process.env.REDIS_URL!);
const redis = new IoredisAdapter({ client: redisClient, subscriber: redisSub });
await redis.loadScripts();

const kms = new AwsKmsAdapter({
  client: new KMSClient({ region: 'us-east-1' }),
  pepper_key_alias: 'alias/agent-auth-pepper',
  device_key_alias: 'alias/agent-auth-device-flow',
  current_version: 1,
  // Your SaaS reads pepper bytes from KMS / SSM and returns them here.
  pepperFetcher: async (_v) => Buffer.alloc(32, 0),
});

// ----- 2. Resolve config --------------------------------------------------
const config = resolveConfig({
  internal_secret: Buffer.from(process.env.AGENT_AUTH_INTERNAL_SECRET!, 'base64'),
  identity_providers: [
    new GitHubAppProvider({
      client_id: process.env.GH_CLIENT_ID!,
      client_secret: process.env.GH_CLIENT_SECRET!,
      webhook_secret: process.env.GH_WEBHOOK_SECRET!,
      app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
    }),
  ],
  storage: { postgres: pg, redis, kms },
  validation: {
    mode: 'strict_uncached',
    local_cache_capacity: 1000,
    local_cache_ttl_ms: 30_000,
    redis_cache_ttl_seconds: 30,
  },
  observability: { service_name: 'my-saas', metric_prefix: 'agent_auth' },
});

// ----- 3. Build the validate-key middleware --------------------------------
const deps = makeValidateKeyDeps(config);
const agentAuthMiddleware = expressMiddleware(deps, {
  docs_url_base: 'https://my-saas.com/docs/agent-auth/errors',
  onAccept: (ctx, request_id) => {
    // Hook for metrics + audit. ctx is the AgentContext.
    void ctx;
    void request_id;
  },
  onReject: (err, request_id) => {
    // Hook for metrics + audit on rejection. err is an AgentAuthError.
    void err;
    void request_id;
  },
});

// ----- 4. Wire the Express app --------------------------------------------
const app = express();
app.use(express.json({ limit: '4kb' }));

// Existing human-auth routes — UNTOUCHED.
// app.use('/api/v1', humanAuth.middleware, ...);

// Mount the agent-auth route family for agents to manage their accounts /
// keys (begin-registration, callback, registration-status, rotate-key,
// revoke, recover-account, webhooks, ...). Wire them however your app
// composes routes. The lib's route handlers are framework-agnostic; the
// adapter you build here translates Express req/res to the handler's
// input shape.

// Protected agent routes:
app.use('/api/agent/v1', agentAuthMiddleware);

app.get('/api/agent/v1/data', (req: Request, res) => {
  const agent = req.agent;
  if (!agent) return res.status(401).json({ error: { code: 'invalid_key' } });

  // Scope guard — throws AgentAuthError(403) caught by your error handler.
  agent.require_scope('read');

  // Tenant isolation: every query scoped by agent.account_id (RT-9).
  // Replace this with your data layer:
  return res.json({
    account_id: agent.account_id,
    key_id: agent.key_id,
    tier: agent.tier,
  });
});

app.post('/api/agent/v1/expensive', (req: Request, res) => {
  const agent = req.agent!;
  agent.require_scope('write');
  if (agent.tier !== 'hot') {
    return res.status(402).json({
      error: { code: 'requires_hot_tier', message: 'Upgrade tier first' },
    });
  }
  return res.json({ status: 'ok' });
});

// ----- 5. Graceful shutdown -----------------------------------------------
async function shutdown() {
  await pg.close().catch(() => undefined);
  await redis.close?.().catch(() => undefined);
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

const port = Number(process.env.PORT) || 8080;
app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`Listening on ${port}`);
});
