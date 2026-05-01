/**
 * Vouch on Cloudflare Workers (Hono adapter).
 *
 * Why Hono on Workers:
 *   - Hono is the fastest path to Vouch on Workers — same API as the
 *     Express adapter, just `app.fetch` is the entry point Workers
 *     expect.
 *   - The validate-key middleware works in any V8/JSCore-style runtime
 *     (Web Crypto subtle, fetch, URL — all standard).
 *
 * Required deps:
 *   npm install agent-auth hono @vouch/client    # if your worker also acts as an agent
 *
 * Storage caveat:
 *   - Postgres: needs a Cloudflare Hyperdrive binding or a HTTP-style
 *     Postgres proxy (e.g. Neon's serverless driver). The lib's
 *     `IoredisAdapter` uses raw TCP and won't work on Workers.
 *   - Redis: use Upstash REST API (or wait for v0.3 Workers-friendly
 *     adapters).
 *   - For the demo below we leave both as `process.env` placeholders
 *     so the example typechecks; real Workers deployment swaps these
 *     for service bindings.
 */

import { Hono } from 'hono';
import { vouch, type AgentContext } from 'agent-auth';
import { honoRoutes, honoAppMiddleware } from 'agent-auth/hono';

declare module 'hono' {
  interface ContextVariableMap {
    agent: AgentContext;
  }
}

interface Env {
  DATABASE_URL: string;
  REDIS_URL: string;
  AGENT_AUTH_INTERNAL_SECRET: string;
  PUBLIC_BASE_URL: string;
  GH_CLIENT_ID: string;
  GH_CLIENT_SECRET: string;
  GH_WEBHOOK_SECRET: string;
  GH_APP_PRIVATE_KEY: string;
  KMS_PEPPER_ALIAS: string;
  KMS_DEVICE_ALIAS: string;
}

let _auth: Promise<Awaited<ReturnType<typeof vouch>>> | null = null;
function getAuth(env: Env) {
  if (_auth) return _auth;
  _auth = vouch({
    database: { url: env.DATABASE_URL },
    redis: { url: env.REDIS_URL },
    kms: {
      provider: 'aws',
      region: 'us-east-1',
      pepper_alias: env.KMS_PEPPER_ALIAS,
      device_alias: env.KMS_DEVICE_ALIAS,
      pepperFetcher: async (_v) => {
        // TODO: read pepper from Workers secret store / KV / D1.
        throw new Error('pepperFetcher not implemented');
      },
    },
    identity: {
      github: {
        client_id: env.GH_CLIENT_ID,
        client_secret: env.GH_CLIENT_SECRET,
        webhook_secret: env.GH_WEBHOOK_SECRET,
        app_private_key_pem: env.GH_APP_PRIVATE_KEY,
      },
    },
    internal_secret: env.AGENT_AUTH_INTERNAL_SECRET,
    base_url: env.PUBLIC_BASE_URL,
  });
  return _auth;
}

const app = new Hono<{ Bindings: Env }>();

// Lazy-build the lifecycle / middleware on first request, then cache.
let _wired = false;
app.use('*', async (c, next) => {
  if (!_wired) {
    const auth = await getAuth(c.env);
    app.route('/agent-auth', honoRoutes(auth));
    app.use('/api/agent/v1/*', honoAppMiddleware(auth));
    _wired = true;
  }
  await next();
});

app.get('/api/agent/v1/whoami', (c) => {
  const agent = c.get('agent');
  return c.json({
    account_id: agent.account_id,
    key_id: agent.key_id,
    scopes: agent.scopes,
    tier: agent.tier,
  });
});

export default app;
