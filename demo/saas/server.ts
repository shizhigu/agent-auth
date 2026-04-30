/**
 * Vouch demo SaaS — minimal Express server demonstrating the full agent-auth
 * lifecycle without external dependencies (no GitHub OAuth, no AWS KMS).
 *
 * Routes:
 *   POST /agent-auth/begin-registration
 *   GET  /__demo/auto-approve  (mock IdP — auto-approves and redirects)
 *   GET  /agent-auth/callback
 *   GET  /agent-auth/registration-status
 *   GET  /api/agent/v1/whoami  (protected — demonstrates `req.agent`)
 *
 * Run: `npm run setup-db && npm run saas` (after `docker compose up -d`).
 */

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import {
  resolveConfig,
  expressMiddleware,
  makeValidateKeyDeps,
  PostgresAdapter,
  IoredisAdapter,
  InMemoryKmsAdapter,
} from 'agent-auth';
import { beginRegistration } from 'agent-auth/routes/begin-registration.js';
import { callback as handleCallback } from 'agent-auth/routes/callback.js';
import { registrationStatus } from 'agent-auth/routes/registration-status.js';
import { sealedBoxReady } from 'agent-auth/crypto/sealed-box.js';
import { createHash } from 'node:crypto';

import { DemoStubProvider } from './stub-provider.js';
import './express-augment.js';

const PORT = Number(process.env.SAAS_PORT) || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// ---------------------------------------------------------------------------
// 1. Adapters
// ---------------------------------------------------------------------------

const pg = new PostgresAdapter({
  pool: { connectionString: process.env.DATABASE_URL! },
  role: 'agent_auth_app',
});

const redisClient = new Redis(process.env.REDIS_URL!);
const redis = new IoredisAdapter({
  client: redisClient,
  subscriber: redisClient.duplicate(),
});
await redis.loadScripts();
await sealedBoxReady();

// In-memory KMS — no AWS dependency. Pepper is deterministic so restarts
// don't invalidate keys minted in the previous session.
const kms = new InMemoryKmsAdapter({
  initial_version: 1,
  initial_pepper: Buffer.alloc(32, 0xa1),
});

// ---------------------------------------------------------------------------
// 2. Stub identity provider — auto-approves on /__demo/auto-approve hit
// ---------------------------------------------------------------------------

const stubProvider = new DemoStubProvider({
  autoApproveBaseUrl: `${BASE_URL}/__demo/auto-approve`,
});

// ---------------------------------------------------------------------------
// 3. Resolve config (the lib's central knob — see SPEC §11.4)
// ---------------------------------------------------------------------------

const config = resolveConfig({
  internal_secret: Buffer.from(process.env.AGENT_AUTH_INTERNAL_SECRET!, 'base64'),
  identity_providers: [stubProvider],
  storage: { postgres: pg, redis, kms },
  observability: { service_name: 'vouch-demo-saas', metric_prefix: 'vouch_demo' },
});

// ---------------------------------------------------------------------------
// 4. Per-request context — IP hash + UA. Real apps pull these from headers.
// ---------------------------------------------------------------------------

function requestContext(req: Request) {
  const ip = req.ip ?? '127.0.0.1';
  const ip_hash = createHash('sha256').update(ip).digest();
  const user_agent = String(req.headers['user-agent'] ?? 'demo');
  return { ip_hash, user_agent };
}

// ---------------------------------------------------------------------------
// 5. App
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json({ limit: '4kb' }));

// ----- 5a. agent-auth lifecycle routes ------------------------------------

app.post('/agent-auth/begin-registration', async (req, res, next) => {
  try {
    const out = await beginRegistration(req.body, {
      postgres: pg,
      identity_providers: [stubProvider],
      redirect_uri: () => `${BASE_URL}/agent-auth/callback`,
      audience: () => 'demo-audience',
      request_context: requestContext(req),
    });
    res.json(out);
  } catch (e) { next(e); }
});

app.get('/agent-auth/callback', async (req, res, next) => {
  try {
    const out = await handleCallback(
      {
        provider: 'demo-stub',
        state: String(req.query.state ?? ''),
        code: String(req.query.code ?? ''),
      },
      {
        postgres: pg,
        kms,
        identity_providers: [stubProvider],
        request_context: requestContext(req),
      },
    );
    // In a real app you'd render an HTML page saying "you can close this tab".
    res.json({ ...out, message: 'Registration callback completed. Agent will fetch via polling.' });
  } catch (e) { next(e); }
});

app.get('/agent-auth/registration-status', async (req, res, next) => {
  try {
    const out = await registrationStatus(
      { poll_token: String(req.query.poll_token ?? '') },
      { postgres: pg, endpoint: 'registration' },
    );
    res.json(out);
  } catch (e) { next(e); }
});

// ----- 5b. demo-only auto-approve route -----------------------------------
// Replaces the human clicking "Authorize" on a real IdP's consent page.
// In production with GitHubAppProvider, this URL would be github.com itself.
app.get('/__demo/auto-approve', (req, res) => {
  const state = String(req.query.state ?? '');
  const redirectUri = String(req.query.redirect_uri ?? '');
  if (!state || !redirectUri) {
    return res.status(400).json({ error: 'missing state or redirect_uri' });
  }
  const callbackUrl =
    `${redirectUri}?state=${encodeURIComponent(state)}&code=demo-${Date.now()}`;
  res.redirect(302, callbackUrl);
});

// ----- 5c. protected routes — middleware validates Bearer token -----------

const validateDeps = makeValidateKeyDeps(config);
app.use('/api/agent/v1', expressMiddleware(validateDeps));

app.get('/api/agent/v1/whoami', (req, res) => {
  if (!req.agent) {
    return res.status(401).json({ error: { code: 'invalid_key' } });
  }
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

// ----- 5d. error handler --------------------------------------------------
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
// 6. Listen + graceful shutdown
// ---------------------------------------------------------------------------

const server = app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Vouch demo SaaS listening on ${BASE_URL}`);
  // eslint-disable-next-line no-console
  console.log(`Now run \`npm run agent\` in another terminal.`);
});

async function shutdown() {
  server.close();
  await pg.close().catch(() => undefined);
  await redis.close?.().catch(() => undefined);
  redisClient.disconnect();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
