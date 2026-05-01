/**
 * Vouch — Hono integration example.
 *
 * Recommended on Cloudflare Workers / Bun / Deno deployments. The shape
 * mirrors `express-integration.ts`: build the auth instance with `vouch()`,
 * mount lifecycle routes with `honoRoutes()`, and protect API routes with
 * `honoAppMiddleware()`.
 */

import { Hono } from 'hono';
import { vouch, type AgentContext } from '@vouch/server';
import { honoRoutes, honoAppMiddleware } from '@vouch/server/hono';

// ----- Type augmentation: c.get('agent') is typed as AgentContext.
declare module 'hono' {
  interface ContextVariableMap {
    agent: AgentContext;
  }
}

// ----- 1. Build the auth instance from a flat config.
const auth = await vouch({
  database: { url: process.env.DATABASE_URL! },
  redis: { url: process.env.REDIS_URL! },
  kms: {
    provider: 'aws',
    region: 'us-east-1',
    pepper_alias: 'alias/vouch-pepper',
    device_alias: 'alias/vouch-device-flow',
    pepperFetcher: async () => Buffer.alloc(32, 0), // your KMS read here
  },
  identity: {
    github: {
      client_id: process.env.GH_CLIENT_ID!,
      client_secret: process.env.GH_CLIENT_SECRET!,
      webhook_secret: process.env.GH_WEBHOOK_SECRET!,
      app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
    },
  },
  internal_secret: process.env.AGENT_AUTH_INTERNAL_SECRET!, // base64 string
  base_url: process.env.PUBLIC_BASE_URL!,
});

// ----- 2. Wire the Hono app.
const app = new Hono();

// Existing human-auth routes are untouched.
// app.use('/api/v1/*', humanAuthMiddleware());

// Mount Vouch's 12 lifecycle routes under /agent-auth.
app.route('/agent-auth', honoRoutes(auth));

// Protect the agent-facing API surface with the validate-key middleware.
app.use('/api/agent/v1/*', honoAppMiddleware(auth));

app.get('/api/agent/v1/whoami', (c) => {
  const agent = c.get('agent');
  return c.json({
    account_id: agent.account_id,
    key_id: agent.key_id,
    scopes: agent.scopes,
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

// ----- 3. Serve.
// Node:        `import { serve } from '@hono/node-server'; serve({ fetch: app.fetch, port: 8080 });`
// Cloudflare:  `export default app;`
// Bun:         `export default { fetch: app.fetch, port: 8080 };`

export default app;
