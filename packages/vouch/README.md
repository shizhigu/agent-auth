# @vouch/server

Server-side core of [Vouch](https://github.com/shizhigu/agent-auth) — identity infrastructure for AI agents. Drop it next to your existing human auth, never replaces it.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/shizhigu/agent-auth/blob/main/LICENSE)
[![Node.js 20+](https://img.shields.io/badge/Node.js-20%2B-brightgreen.svg)](https://nodejs.org)

## Install

```bash
npm install @vouch/server pg ioredis @aws-sdk/client-kms libsodium-wrappers
# Plus your framework:
npm install express        # OR: npm install hono
```

## 15-line quick start (Express)

```ts
import express from 'express';
import { vouch } from '@vouch/server';

const auth = await vouch({
  database: { url: process.env.DATABASE_URL! },
  redis: { url: process.env.REDIS_URL! },
  kms: {
    provider: 'aws',
    region: 'us-east-1',
    pepper_alias: 'alias/vouch-pepper',
    device_alias: 'alias/vouch-device-flow',
    pepperFetcher: async (v) => /* read pepper bytes from KMS */ Buffer.alloc(32),
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

const app = express();
auth.express.mount(app);                                 // /agent-auth/*
app.use('/api/agent/v1', auth.express.middleware());     // protect your API

app.get('/api/agent/v1/whoami', (req, res) => {
  res.json({ account_id: req.agent!.account_id, scopes: req.agent!.scopes });
});

app.listen(8080);
```

## What's inside

The lib does the things a SaaS-side agent auth needs:

- 12 lifecycle routes (begin / callback / status / rotate / revoke / recover / webhooks / healthz / well-known / list-keys)
- Identity providers: GitHub, Google, generic OIDC, custom
- HMAC + KMS-pepper validation; cache-hit P99 ≈ 3 µs
- Sealed-box (libsodium) one-shot bearer-key delivery
- Postgres-authoritative state + Redis 30 s cache
- Append-only audit hash chain + WORM mirror
- Multi-region active-passive with LSN barrier
- GCRA rate limiting, OTel tracing, structured logs

## Companion packages

| Package | Use |
|---|---|
| [`@vouch/server`](https://www.npmjs.com/package/@vouch/server) | this — server-side lib |
| [`@vouch/client`](https://www.npmjs.com/package/@vouch/client) | agent-side SDK (5-line `register()` + sealed-box decrypt + bearer-injecting `fetch`) |
| [`@vouch/cli`](https://www.npmjs.com/package/@vouch/cli) | `vouch migrate up/down/status` |
| [`create-vouch-app`](https://www.npmjs.com/package/create-vouch-app) | `npx create-vouch-app my-saas` scaffolder |

## Documentation

- [Full README + comparison vs Better Auth / Auth0 / Clerk](https://github.com/shizhigu/agent-auth#readme)
- [Getting started guide](https://github.com/shizhigu/agent-auth/blob/main/apps/docs/getting-started.md)
- [Concepts: architecture + state machines](https://github.com/shizhigu/agent-auth/blob/main/apps/docs/concepts.md)
- [Identity providers](https://github.com/shizhigu/agent-auth/blob/main/apps/docs/providers.md)
- [Lifecycle routes reference](https://github.com/shizhigu/agent-auth/blob/main/apps/docs/reference/lifecycle.md)
- [SPEC.md](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md) — comprehensive spec, threat model, ADRs, runbooks
- [Threat model](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md#part-vi--threat-model) — 32/44 RT-* threats covered with tests

## License

[MIT](https://github.com/shizhigu/agent-auth/blob/main/LICENSE) © 2026 Agentic Flow LLC
