/**
 * {{name}} — a SaaS using Vouch for agent authentication.
 */
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { vouch } from '@vouch/server';

import './express-augment.js';

const PORT = Number(process.env.PORT) || 8080;

// ---------------------------------------------------------------------------
// 1. Build the auth instance.
// ---------------------------------------------------------------------------

const auth = await vouch({
  database: { url: process.env.DATABASE_URL! },
  redis: { url: process.env.REDIS_URL! },
  kms: {
    provider: 'aws',
    region: process.env.AWS_REGION ?? 'us-east-1',
    pepper_alias: process.env.KMS_PEPPER_ALIAS!,
    device_alias: process.env.KMS_DEVICE_ALIAS!,
    pepperFetcher: async (_v) => {
      // Read the pepper bytes from KMS / SSM / your secret manager and
      // return a 32-byte Buffer. See SPEC §6.1.2 for the rotation policy.
      throw new Error('TODO: implement pepperFetcher (read from KMS)');
    },
  },
  identity: {
    github: {
      client_id: process.env.GH_CLIENT_ID!,
      client_secret: process.env.GH_CLIENT_SECRET!,
      webhook_secret: process.env.GH_WEBHOOK_SECRET!,
      app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
    },
  },
  internal_secret: process.env.AGENT_AUTH_INTERNAL_SECRET!,
  base_url: process.env.PUBLIC_BASE_URL!,
});

// ---------------------------------------------------------------------------
// 2. Wire the Express app.
// ---------------------------------------------------------------------------

const app = express();

// Mount Vouch BEFORE any global JSON parser. mount() handles webhook
// raw-body parsing for HMAC signature verification.
auth.express.mount(app);

app.use(express.json());

// Existing human-auth routes are untouched.
// app.use('/api/v1', humanAuthMiddleware());

// Protected agent API routes.
app.use('/api/agent/v1', auth.express.middleware());

app.get('/api/agent/v1/whoami', (req, res) => {
  if (!req.agent) return res.status(401).json({ error: { code: 'invalid_key' } });
  res.json({
    account_id: req.agent.account_id,
    key_id: req.agent.key_id,
    scopes: req.agent.scopes,
    tier: req.agent.tier,
  });
});

// Error handler.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const e = err as { status?: number; code?: string; message?: string };
  console.error('[server error]', err);
  res.status(e.status ?? 500).json({
    error: { code: e.code ?? 'internal', message: e.message ?? 'Internal error' },
  });
});

// ---------------------------------------------------------------------------
// 3. Listen + graceful shutdown.
// ---------------------------------------------------------------------------

const server = app.listen(PORT, () => {
  console.log(`{{name}} listening on http://localhost:${PORT}`);
});

async function shutdown() {
  server.close();
  await auth.shutdown();
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
