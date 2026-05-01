# Vouch on SvelteKit

Drop the catch-all endpoint into a SvelteKit project to mount Vouch:

```
your-app/
└── src/routes/agent-auth/[...rest]/+server.ts
```

## Install

```bash
npm install agent-auth pg ioredis @aws-sdk/client-kms libsodium-wrappers
```

## Env vars

Add to `.env` (SvelteKit auto-loads via `$env/dynamic/private`):

```
DATABASE_URL=postgres://…
REDIS_URL=redis://…
AGENT_AUTH_INTERNAL_SECRET=<32-byte base64>
PUBLIC_BASE_URL=https://your-app.com

AWS_REGION=us-east-1
KMS_PEPPER_ALIAS=alias/vouch-pepper
KMS_DEVICE_ALIAS=alias/vouch-device-flow

GH_CLIENT_ID=...
GH_CLIENT_SECRET=...
GH_WEBHOOK_SECRET=...
GH_APP_PRIVATE_KEY=...
```

## Notes

- `[...rest]` is SvelteKit's catch-all syntax — matches everything under `/agent-auth/*`.
- The Vouch instance is module-scoped — SvelteKit's adapter-node keeps connection pools alive across requests within a worker.
- For protected API routes, follow the same pattern: `validateBearer(bearer)` at the top of `+server.ts` and use `agent.account_id` to scope queries.
- Migrations: run `npx vouch migrate up` outside SvelteKit (e.g. in a CI step).
- Workers / Cloudflare adapter: Postgres + Redis need Hyperdrive + Upstash; same caveat as Next.js.
