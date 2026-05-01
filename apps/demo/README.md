# Vouch demo — end-to-end in 5 minutes

A minimal, runnable demo of the full Vouch lifecycle:

> **Agent generates keypair → registers via stub IdP → polls for completion → decrypts sealed-box bearer key → calls a protected API.**

No GitHub OAuth setup, no AWS KMS, no docs you'll skim. Just `docker compose up` + 2 commands.

## What this demo proves

1. The lib's server-side routes (`beginRegistration` → `callback` → `registrationStatus`) wire together cleanly behind Express.
2. An agent script can drive the full flow programmatically: generate Curve25519 keypair, hit the IdP, poll, decrypt sealed-box, present Bearer.
3. The `expressMiddleware` populates `req.agent` correctly from the bearer key.
4. Postgres + Redis + an in-memory KMS adapter are sufficient for local dev — no AWS account needed.

This is the **server-side** flow today. v0.2 will ship `@vouch/client` so the agent code in `agent/run.ts` becomes ~5 lines.

## How to run

Prereqs: **Docker**, **Node 20+**, **psql** (the Postgres CLI; `brew install libpq` on macOS).

### One-time setup

```bash
# 1. Install + build everything from the repo root (workspace install).
cd /path/to/agent-auth
npm install
npm run build

# 2. Configure the demo
cd apps/demo
cp .env.example .env

# 3. Start Postgres + Redis
docker compose up -d

# 4. Apply migrations (also grants role membership to the postgres user)
set -a && source .env && set +a
npm run setup-db
```

### Running the demo

Open two terminals.

**Terminal 1 — the SaaS:**
```bash
cd apps/demo
set -a && source .env && set +a
npm run saas
# -> Vouch demo SaaS listening on http://localhost:3000
```

**Terminal 2 — the agent:**
```bash
cd apps/demo
set -a && source .env && set +a
npm run agent
```

Expected output (terminal 2):

```
[1/6] Generated agent keypair (pubkey=afvIzV8tPsMD...)
[2/6] Got poll_token=pak_goh5B-51... + challenge_url
[3/6] Auto-approved (in production: human clicks "Authorize" on IdP)
[4/6] Registration completed (account_id=601dd215-..., first_key=true)
[5/6] Decrypted bearer key (key=pak_..., key_id=agk_..., tier=cold)
[6/6] Hit /api/agent/v1/whoami: {
  account_id: '601dd215-36fb-4c4a-...',
  key_id: 'agk_...',
  identity: { provider: 'demo-stub', subject: 'demo-user-...', ... },
  scopes: [ 'read', 'self:rotate' ],
  tier: 'cold'
}

Done. Agent successfully registered and called a protected API.
```

## What each piece does

| File | Role |
|---|---|
| `docker-compose.yml` | Postgres 16 + Redis 7 on non-default ports (`55432` / `56379`) |
| `scripts/setup-db.sh` | Applies `packages/vouch/schema/migrations/0001..0006.sql` from the repo |
| `saas/server.ts` | Express SaaS — wires the lib's lifecycle routes + protected `/api/agent/v1/whoami` |
| `saas/stub-provider.ts` | Auto-approving `IdentityProvider` (replaces GitHub OAuth for local dev) |
| `agent/run.ts` | Node script that drives the agent side of the flow end-to-end |

## What's deliberately stripped vs production

| | Demo | Production |
|---|---|---|
| Identity provider | Stub auto-approves | `GitHubAppProvider` (real OAuth + PKCE) |
| KMS | `InMemoryKmsAdapter` (deterministic pepper) | `AwsKmsAdapter` (KMS-managed pepper, weekly rotation) |
| Audit WORM | not configured | `AwsS3WormPutter` to S3 Object Lock |
| Multi-region | not configured | LSN barrier + `MultiRegionConfig` |
| Rate limiting | not enforced on routes | GCRA per-IP + per-account at the edge |
| Webhook secrets | n/a (no webhooks here) | dual-secret rotation window |
| Owner-approval recovery | not exercised | `emitOwnerApprovalRequest` + signed approval |
| Logging / metrics / tracing | bare `console.log` | `createLogger` + `MetricsRegistry` (+ OTel in v0.2) |

For the production wiring see [`examples/express-integration.ts`](../../examples/express-integration.ts) at the repo root.

## Cleanup

```bash
docker compose down -v   # also wipes the database volume
```

## Troubleshooting

**"begin-registration failed: idp_circuit_open"** — the stub provider threw. Check the SaaS logs; usually a typecheck issue in `stub-provider.ts`.

**"registration timed out"** — the auto-approve redirect didn't trigger the callback. Hit `http://localhost:3000/__demo/auto-approve?state=anything&redirect_uri=http://localhost:3000/agent-auth/callback` directly to verify the route returns 302.

**"Cannot find module 'agent-auth'"** — you need to `npm run build` in the repo root first; the demo installs the lib via `file:..` which expects `dist/` to exist.

**Sealed-box decrypt error** — the agent's keypair didn't survive the request. Don't restart the agent script between begin-registration and registration-status polling.

## Going further

Once this works, look at [`examples/express-integration.ts`](../../examples/express-integration.ts) for the full production wiring (real GitHub App provider, KMS, scopes, error handlers), and [`examples/worker-cronjobs.ts`](../../examples/worker-cronjobs.ts) for the background workers (audit chain verifier, rotation grace expirer, idempotency reconciler, etc.).
