/**
 * agent-auth — Hono integration example.
 *
 * Hono is the recommended choice for Cloudflare Workers / Bun-style
 * deployments; the lib's `honoMiddleware` follows the same surface as the
 * Express adapter (req.agent equivalent: `c.get('agent')`).
 */

import { Hono } from 'hono';
import { Pool } from 'pg';
import { Redis } from 'ioredis';
import { KMSClient } from '@aws-sdk/client-kms';

import {
  resolveConfig,
  honoMiddleware,
  makeValidateKeyDeps,
  PostgresAdapter,
  IoredisAdapter,
  AwsKmsAdapter,
  type AgentContext,
} from 'agent-auth';
import { GitHubAppProvider } from 'agent-auth/identity/github-app/browser-flow.js';

// ----- Type augmentation (exactly once) -----------------------------------
declare module 'hono' {
  interface ContextVariableMap {
    agent: AgentContext;
  }
}

// ----- 1. Build adapters (same as Express example) ------------------------
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
  pepperFetcher: async () => Buffer.alloc(32, 0),
});

// ----- 2. Resolve config --------------------------------------------------
const config = resolveConfig({
  internal_secret: Buffer.from(process.env.AGENT_AUTH_INTERNAL_SECRET!, 'base64'),
  identity_providers: [
    new GitHubAppProvider({
      client_id: process.env.GH_CLIENT_ID!,
      client_secret: process.env.GH_CLIENT_SECRET!,
      webhook_secret: process.env.GH_WEBHOOK_SECRET!,
    }),
  ],
  storage: { postgres: pg, redis, kms },
});

// ----- 3. Build the middleware --------------------------------------------
const deps = makeValidateKeyDeps(config);
const agentAuth = honoMiddleware(deps, {
  docs_url_base: 'https://my-saas.com/docs/agent-auth/errors',
});

// ----- 4. Wire the Hono app -----------------------------------------------
const app = new Hono();

// Global error handler — Hono's onError is where AgentAuthError thrown from
// inside route handlers (e.g. agent.require_scope()) lands. Translate to
// the §10.3 wire shape.
app.onError((err, c) => {
  if (err && typeof err === 'object' && 'code' in err && 'status' in err) {
    const e = err as { status: number; code: string; message?: string };
    return c.json(
      { error: { code: e.code, message: e.message ?? e.code } },
      // hono types: status is a numeric union — cast as needed.
      e.status as 200,
    );
  }
  return c.json({ error: { code: 'internal_error', message: 'unexpected' } }, 500);
});

// Existing human-auth routes go here — untouched.
// app.use('/api/v1/*', humanAuthMiddleware());

// Protected agent routes:
app.use('/api/agent/v1/*', agentAuth);

app.get('/api/agent/v1/data', (c) => {
  const agent = c.get('agent');
  agent.require_scope('read');
  return c.json({
    account_id: agent.account_id,
    key_id: agent.key_id,
    tier: agent.tier,
  });
});

app.post('/api/agent/v1/expensive', (c) => {
  const agent = c.get('agent');
  agent.require_scope('write');
  if (agent.tier !== 'hot') {
    return c.json(
      { error: { code: 'requires_hot_tier', message: 'Upgrade tier first' } },
      402,
    );
  }
  return c.json({ status: 'ok' });
});

export default app;
