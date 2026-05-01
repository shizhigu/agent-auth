/**
 * Vouch demo SaaS — minimal Express server demonstrating the full lifecycle
 * with the high-level `vouch()` factory.
 *
 * Replaces the 60-line "wire each adapter manually" pattern with ~15 lines
 * of intentional config. Running this server end-to-end with the agent
 * script in `../agent/run.ts` is the canonical check that the factory's
 * dispatcher routes correctly to begin-registration / callback /
 * registration-status / etc.
 *
 * Run: `npm run setup-db && npm run saas` (after `docker compose up -d`).
 */

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { vouch } from 'agent-auth';

import { DemoStubProvider } from './stub-provider.js';
import './express-augment.js';

const PORT = Number(process.env.SAAS_PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// ---------------------------------------------------------------------------
// 1. Build Vouch — the factory handles adapters, sealedBoxReady, dispatcher.
// ---------------------------------------------------------------------------

const stubProvider = new DemoStubProvider({
  autoApproveBaseUrl: `${BASE_URL}/__demo/auto-approve`,
});

const auth = await vouch({
  database: { url: process.env.DATABASE_URL! },
  redis: { url: process.env.REDIS_URL! },
  kms: { provider: 'in-memory', pepper: Buffer.alloc(32, 0xa1) },
  // The demo uses a stub identity provider (no GitHub OAuth setup needed).
  // Real SaaS would use `identity: { github: { client_id, client_secret, ... } }`.
  identity: { custom: [stubProvider] },
  internal_secret: Buffer.from(process.env.AGENT_AUTH_INTERNAL_SECRET!, 'base64'),
  base_url: BASE_URL,
  observability: { service_name: 'vouch-demo-saas', metric_prefix: 'vouch_demo' },
});

// ---------------------------------------------------------------------------
// 2. Wire the Express app.
// ---------------------------------------------------------------------------

const app = express();

// Mount Vouch BEFORE any global JSON parser. mount() handles webhook raw body
// + JSON for the rest of the lifecycle routes internally.
auth.express.mount(app);

// Now the rest of your app's routes can use the global JSON parser.
app.use(express.json());

// ----- Demo-only auto-approve route — replaces the human clicking
// "Authorize" on a real IdP. Mounted AFTER auth.express.mount() so
// the dispatcher takes precedence for /agent-auth/*.
app.get('/__demo/auto-approve', (req, res) => {
  const state = String(req.query.state ?? '');
  const redirectUri = String(req.query.redirect_uri ?? '');
  if (!state || !redirectUri) {
    return res.status(400).json({ error: 'missing state or redirect_uri' });
  }
  const callbackUrl = `${redirectUri}?state=${encodeURIComponent(state)}&code=demo-${Date.now()}`;
  res.redirect(302, callbackUrl);
});

// ----- Protected agent API routes.
app.use('/api/agent/v1', auth.express.middleware());

app.get('/api/agent/v1/whoami', (req, res) => {
  if (!req.agent) return res.status(401).json({ error: { code: 'invalid_key' } });
  res.json({
    account_id: req.agent.account_id,
    key_id: req.agent.key_id,
    identity: {
      provider: req.agent.identity.provider,
      subject: req.agent.identity.subject,
      display_handle: req.agent.identity.display_handle,
    },
    scopes: req.agent.scopes,
    tier: req.agent.tier,
  });
});

// ----- Error handler.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const e = err as { status?: number; code?: string; message?: string };
  // eslint-disable-next-line no-console
  console.error('[saas error]', err);
  res.status(e.status ?? 500).json({
    error: { code: e.code ?? 'internal', message: e.message ?? 'Internal error' },
  });
});

// ---------------------------------------------------------------------------
// 3. Listen + graceful shutdown.
// ---------------------------------------------------------------------------

const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Vouch demo SaaS listening on ${BASE_URL}`);
  // eslint-disable-next-line no-console
  console.log(`Now run \`npm run agent\` in another terminal.`);
});

async function shutdown() {
  server.close();
  await auth.shutdown();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
