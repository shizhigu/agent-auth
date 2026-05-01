# Vouch examples

Reference integrations across runtimes + frameworks.

## Single-file (typechecked in CI)

| File | What it shows |
|---|---|
| [`express-integration.ts`](express-integration.ts) | Full Express SaaS — `vouch()` factory + `auth.express.mount()` + protected routes + graceful shutdown. The canonical "real production wiring" example. |
| [`hono-integration.ts`](hono-integration.ts) | Same SaaS, Hono variant — `auth.hono.routes()` + `honoAppMiddleware()`. Runs on Node, Bun, Deno. |
| [`worker-cronjobs.ts`](worker-cronjobs.ts) | The 8 background jobs the lib expects you to schedule (audit-chain verifier, rotation-grace expirer, idempotency reconciler, expired-rows reaper, processAgentJobs worker, partition manager, webhook replay, Redis-set reconciler). |

## Framework-specific (in subdirectories)

| Directory | Runtime |
|---|---|
| [`nextjs-app-router/`](nextjs-app-router/) | **Next.js 14+ App Router** — catch-all Route Handler at `app/agent-auth/[...path]/route.ts` plus an example protected route. |
| [`sveltekit/`](sveltekit/) | **SvelteKit** — catch-all endpoint at `src/routes/agent-auth/[...rest]/+server.ts`. |
| [`cloudflare-workers/`](cloudflare-workers/) | **Cloudflare Workers** — Hono on Workers via `app.fetch` + `wrangler.toml`. Storage caveat: requires Hyperdrive / Upstash for Postgres / Redis. |

## What's inside each subdirectory

A `README.md` with install + deployment instructions, and just enough wiring code for you to drop into a real project. They aren't standalone runnable npm packages — they're meant to be copy-pasted into your own framework setup.
