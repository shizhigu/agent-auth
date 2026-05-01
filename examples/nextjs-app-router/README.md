# Vouch on Next.js (App Router)

Drop these two files into a Next.js 14+ App Router project to mount Vouch:

```
your-app/
├── app/
│   ├── agent-auth/[...path]/route.ts   ← lifecycle dispatcher
│   └── api/
│       └── agent/v1/whoami/route.ts    ← example protected route
```

## Install

```bash
npm install agent-auth pg ioredis @aws-sdk/client-kms libsodium-wrappers
```

## Env vars

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

- The lifecycle catch-all uses `auth.lifecycle.*` directly — `auth.express` is for Express, not Next.js Route Handlers.
- The Vouch instance is module-scope-cached so connection pools survive across requests within the same Next.js function instance.
- Migrations: run `npx vouch migrate up` outside the Next.js runtime (e.g. in a CI step before deploy, or via `prebuild` in package.json).
- For Edge runtime: Postgres and Redis aren't available out of the box — use Hyperdrive for Postgres and Upstash for Redis (or wait for v0.3 Workers-friendly adapters).
