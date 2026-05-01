# Vouch on Cloudflare Workers

Use the Hono adapter — same lifecycle dispatcher, same middleware, just `app.fetch` is the entrypoint Workers expect.

```
your-worker/
├── worker.ts        ← copy from this example
└── wrangler.toml    ← copy from this example
```

## Install

```bash
npm install agent-auth hono
npm install -D wrangler @cloudflare/workers-types
```

## Storage caveat

Cloudflare Workers can't open raw TCP sockets. The lib's bundled `pg` and `ioredis` adapters need TCP, so you'll either:

- **Postgres** — use [Cloudflare Hyperdrive](https://developers.cloudflare.com/hyperdrive/) (proxies Postgres over Cloudflare's network) OR Neon's [serverless driver](https://neon.tech/docs/serverless/serverless-driver) (HTTP-tunneled Postgres).
- **Redis** — use Upstash's [REST API](https://upstash.com/docs/redis/features/restapi) wrapped to look like an `IoredisAdapter`, OR wait for v0.3's Workers-friendly adapter.

Until v0.3 ships dedicated Workers adapters, the cleanest path is "Workers in front of a regular Postgres + Redis" via Hyperdrive — your Worker calls `vouch()` once with the Hyperdrive connection string, and the lib doesn't need to know it's running on Workers.

## Deploy

```bash
wrangler secret put AGENT_AUTH_INTERNAL_SECRET
wrangler secret put DATABASE_URL
wrangler secret put REDIS_URL
# ... etc

wrangler deploy
```

## Migrations

Workers can't run migrations directly (no filesystem access for SQL files). Run `npx vouch migrate up` from a regular machine (CI runner, your laptop) before deploying the Worker, then deploy. The Worker reads from the migrated database.
