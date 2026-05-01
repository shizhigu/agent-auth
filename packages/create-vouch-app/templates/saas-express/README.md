# {{name}}

{{description}}

Built on [Vouch](https://github.com/shizhigu/agent-auth) — identity infrastructure for AI agents.

## Quick start

```bash
# 1. Install + configure
cp .env.example .env
# Generate the internal secret:
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
# (Paste it into .env as AGENT_AUTH_INTERNAL_SECRET)

# Set up your GitHub App credentials in .env:
#   GH_CLIENT_ID, GH_CLIENT_SECRET, GH_WEBHOOK_SECRET, GH_APP_PRIVATE_KEY

# 2. Bring up local Postgres + Redis
docker compose up -d

# 3. Apply migrations
npx vouch migrate up

# 4. Start the server
npm run dev
# -> {{name}} listening on http://localhost:8080
```

## What's wired up

- `POST /agent-auth/begin-registration` — agent starts registration
- `GET /agent-auth/callback` — GitHub OAuth callback
- `GET /agent-auth/registration-status` — agent polls for completion
- `POST /agent-auth/rotate-key`, `/revoke`, `/recover-account*` — key lifecycle
- `POST /agent-auth/webhooks/:provider` — IdP webhooks (raw-body verified)
- `GET /agent-auth/healthz`, `/well-known` — operational endpoints
- `GET /api/agent/v1/whoami` — example protected route (replace with your own)

`req.agent` is populated by Vouch's middleware on protected routes; `req.user` is reserved for your existing human auth.

## Production checklist

Before going live:

- [ ] Replace the `pepperFetcher` placeholder in `src/server.ts` with a real KMS read.
- [ ] Configure WORM audit storage (S3 Object Lock) — see `agent-auth` SPEC §6.4.2.
- [ ] Set up rate limiting (`rate_limit` config option).
- [ ] Run integration + chaos tests against your deployment.
- [ ] Configure observability (`observability` config option) and ship logs/metrics to your APM.

## Documentation

- [Vouch SPEC](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md)
- [Threat model](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md#part-vi--threat-model)
- [Runbooks](https://github.com/shizhigu/agent-auth/tree/main/docs/runbooks)
- [Examples](https://github.com/shizhigu/agent-auth/tree/main/examples)

## License

MIT — see [LICENSE](https://github.com/shizhigu/agent-auth/blob/main/LICENSE).
