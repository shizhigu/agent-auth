# Hono integration

Vouch's Hono adapter mirrors the Express one but runs on Bun, Cloudflare Workers, and Deno.

## Mount

```ts
import { Hono } from 'hono';
import { vouch } from 'agent-auth';
import { honoRoutes, honoAppMiddleware } from 'agent-auth/hono';

const auth = await vouch({ /* same config as Express */ });

const app = new Hono();
app.route('/agent-auth', honoRoutes(auth));            // 12 lifecycle routes
app.use('/api/agent/v1/*', honoAppMiddleware(auth));   // protect your API

app.get('/api/agent/v1/whoami', (c) => {
  const agent = c.get('agent');
  return c.json({ account_id: agent.account_id, scopes: agent.scopes });
});

export default app;
```

## Type augmentation

```ts
import type { AgentContext } from 'agent-auth';

declare module 'hono' {
  interface ContextVariableMap {
    agent: AgentContext;
  }
}
```

After this, `c.get('agent')` is typed as `AgentContext` (per SPEC §6.3 — not `c.get('user')`).

## Runtime targets

### Node

```ts
import { serve } from '@hono/node-server';
serve({ fetch: app.fetch, port: 8080 });
```

### Cloudflare Workers

```ts
export default app;
```

::: warning
Postgres / Redis access from Workers needs a service binding (Hyperdrive for Postgres; Upstash REST API or a service-binding adapter for Redis). The lib's `IoredisAdapter` uses raw TCP, which Workers doesn't allow. v0.3 will ship Workers-compatible adapters.
:::

### Bun

```ts
export default { fetch: app.fetch, port: 8080 };
```

Bun's `pg` + `ioredis` work natively — no special config.

### Deno

```ts
Deno.serve({ port: 8080 }, app.fetch);
```

## Why use Hono over Express?

Top reasons our SaaS users have switched:

- **Bun + Cloudflare Workers** — Hono is native; Express requires `@hono/node-server`-style polyfills.
- **Type-safe routing** — Hono's path params + middleware are strongly typed.
- **Smaller cold-start** — Hono is ~30 KB; Express + body-parser + cookie-parser is several MB.
- **Web-standards Request/Response** — Hono uses the platform `fetch` types; easier to share code with the agent SDK side.

The same `auth.lifecycle` backs both — there's no behavioral difference between mounting via Express vs Hono.
