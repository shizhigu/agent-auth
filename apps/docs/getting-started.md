# Getting started

Vouch is the open-source auth rail for AI agents. This guide gets you from zero to a working SaaS that can issue and validate agent API keys in **5 minutes**.

## Prerequisites

- **Node 20+**
- **Docker** (for local Postgres + Redis)
- **psql** (the Postgres CLI; `brew install libpq` on macOS)

## Scaffold a project

```bash
npx create-vouch-app my-saas
cd my-saas
```

That writes a working Express template with:
- `src/server.ts` — Vouch wired up via `vouch()` factory
- `docker-compose.yml` — local Postgres + Redis on non-default ports
- `.env.example` — all the environment variables you need
- `package.json` — npm scripts for dev, build, migrate

::: tip Different shape?
- `--template agent` writes a Node agent script using `@vouch/client` instead.
- `--description "..."` populates the generated README + package.json.
:::

## Configure secrets

```bash
cp .env.example .env

# Generate a 32-byte internal_secret
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
# (paste it into .env as AGENT_AUTH_INTERNAL_SECRET)
```

You'll also need a GitHub App (or a Google / generic OIDC client). For GitHub:
1. Go to <https://github.com/settings/apps/new>
2. Set Callback URL to `http://localhost:8080/agent-auth/callback`
3. Set User permissions → "Read user" → access
4. Generate a private key + webhook secret
5. Copy the values into `.env`:
   - `GH_CLIENT_ID`, `GH_CLIENT_SECRET`
   - `GH_WEBHOOK_SECRET`
   - `GH_APP_PRIVATE_KEY` (the .pem contents)

::: details Don't have GitHub credentials yet?
Use Google: set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`, swap `identity.github` for `identity.google` in `src/server.ts`. Or run the [end-to-end demo](/guides/demo) which uses an auto-approving stub provider — no IdP setup at all.
:::

## Bring up local services

```bash
docker compose up -d
```

This starts:
- Postgres 16 on `localhost:55432`
- Redis 7 on `localhost:56379`

## Apply migrations

```bash
npx vouch migrate up
```

`vouch migrate up` applies the bundled SQL files in order, wraps each in a transaction, and tracks state in a `vouch_migrations` table. Re-running is idempotent. See [the migrate CLI guide](/cli) for status + rollback.

## Start the server

```bash
npm install
npm run dev
# -> my-saas listening on http://localhost:8080
```

The 12 lifecycle routes are mounted under `/agent-auth/*`:

| Route | What it does |
|---|---|
| `POST /agent-auth/begin-registration` | agent starts registration |
| `GET /agent-auth/callback` | IdP OAuth callback |
| `GET /agent-auth/registration-status` | agent polls for completion |
| `POST /agent-auth/rotate-key` | rotate an agent key (auth required) |
| `POST /agent-auth/revoke` | revoke a key (auth required) |
| `POST /agent-auth/recover-account` | cross-device recovery flow |
| `POST /agent-auth/recover-account-confirm/:token` | owner-approve recovery |
| `GET /agent-auth/recover-account-status` | recovery polling |
| `POST /agent-auth/webhooks/:provider` | IdP webhooks (raw-body verified) |
| `GET /agent-auth/healthz` | health check |
| `GET /agent-auth/well-known` | client capability discovery |
| `GET /agent-auth/list-keys` | list keys for a caller (auth required) |

Plus your own protected routes under `/api/agent/v1/*` — `req.agent` is populated automatically by the middleware.

## Connect an agent

The fastest way to verify everything works:

```bash
npx create-vouch-app my-agent --template agent
cd my-agent
cp .env.example .env  # set SAAS_BASE_URL=http://localhost:8080
npm install
npm run dev
```

The agent will:
1. Generate a Curve25519 keypair.
2. POST `/agent-auth/begin-registration` with the public key.
3. Print the IdP authorization URL — open it in a browser, click "Authorize".
4. Poll `/agent-auth/registration-status` until the SaaS has issued a key.
5. Sealed-box decrypt the encrypted payload → bearer token (`pak_…`).
6. Call `/api/agent/v1/whoami` with the bearer.

::: tip All in one terminal?
The same SDK that the agent template uses ([`@vouch/client`](/client-sdk)) is fetch-compatible: `await vouch.fetch('/api/agent/v1/whoami')` automatically injects the Bearer header. Persist `vouch.bearer` in the OS keychain to skip re-registration on subsequent runs.
:::

## What's next

- **[Concepts →](/concepts)** — how the Postgres / Redis / KMS / sealed-box pieces fit together.
- **[Identity providers →](/providers)** — GitHub, Google, generic OIDC, custom.
- **[Migrate CLI →](/cli)** — `vouch migrate` reference.
- **[Threat model →](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md#part-vi--threat-model)** — 44 RT-* threats with mitigations.
