# End-to-end demo

`apps/demo/` is a runnable end-to-end Vouch lifecycle without any external services — no GitHub OAuth, no AWS KMS. Just `docker compose up` + 2 commands.

## What this demo proves

1. The lib's server-side routes (`beginRegistration` → `callback` → `registrationStatus`) wire together cleanly behind Express.
2. An agent script can drive the full flow programmatically: generate Curve25519 keypair, hit the IdP, poll, decrypt sealed-box, present Bearer.
3. `auth.express.middleware()` populates `req.agent` correctly from the bearer key.
4. Postgres + Redis + an in-memory KMS adapter are sufficient for local dev.

This is the **server-side** flow today. For the agent side use `@vouch/client` — the SDK distills the agent script in `apps/demo/agent/run.ts` to ~5 lines.

## How to run

Prereqs: Docker, Node 20+, psql.

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

## What's deliberately stripped vs production

| | Demo | Production |
|---|---|---|
| Identity provider | Stub auto-approves | `GitHubAppProvider` (real OAuth + PKCE) |
| KMS | `InMemoryKmsAdapter` (deterministic pepper) | `AwsKmsAdapter` (KMS-managed pepper, weekly rotation) |
| Audit WORM | not configured | `AwsS3WormPutter` to S3 Object Lock |
| Multi-region | not configured | LSN barrier + `MultiRegionConfig` |
| Rate limiting | not enforced | GCRA per-IP + per-account at the edge |
| Owner-approval recovery | not exercised | `emitOwnerApprovalRequest` + signed approval |
| Logging / metrics | bare `console.log` | `createLogger` + `MetricsRegistry` (+ OTel in v0.3) |

For the production wiring, see [`examples/express-integration.ts`](https://github.com/shizhigu/agent-auth/blob/main/examples/express-integration.ts) at the repo root.

## Cleanup

```bash
docker compose down -v   # also wipes the database volume
```
