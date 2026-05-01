# FAQ

## How is Vouch different from Better Auth / Auth0 / Clerk?

They handle **human** auth — sessions, signup, MFA, password resets. Vouch handles **agent** auth — issuing scoped API keys to AI agents on behalf of a human owner. The two run side by side: `req.user` is your human-auth lib's slot; `req.agent` is Vouch's. Per [SPEC §6.3](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md), this separation is a deliberate confused-deputy guard.

## Why not just have the agent share the human's password / API key?

Three problems:
1. **Unauditable** — every action shows up as the human, no way to attribute or scope.
2. **Hard to scope** — the API key has every permission the human has. Agents shouldn't need write access to delete-account.
3. **Hard to revoke** — revoking the agent revokes the human, and vice versa.

Vouch issues the agent its own first-class identity, scoped to a single tenant, with its own audit trail and instant revocation.

## Is the SaaS-side library production-ready?

The OSS engine is feature-complete (8 milestones, 355+ unit + 94 integration + 14 chaos tests). The spec was audited across 13 rounds with codex / GPT-5; final grade A.

What's NOT production-ready yet:
- **Hosted Cloud** — self-host only at v0.1.
- **Admin dashboard** — CLI runbooks only (no web UI).

For self-hosting at scale you'll still need to set up KMS, S3 Object Lock, multi-region replication, audit retention, runbook execution, etc. — the lib doesn't do those for you, but they're documented in [SPEC §11.2 M6+](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md).

## What about Auth0-for-AI-Agents / Nango / Arcade?

Those are **token vaults** — they help your code call third-party APIs (Slack, Google Drive) on behalf of an authenticated human. Vouch is the inverse direction: your SaaS *is* the third party, and an agent is the caller.

If you're building Acme SaaS and want Claude Code to autonomously sign up for an Acme account on a human's behalf and call the Acme API, **Vouch fills that gap**. None of the others do.

## How do I rotate / revoke a key?

Built-in lifecycle routes:
- `POST /agent-auth/rotate-key` — agent self-rotates (requires `self:rotate` scope, ships by default).
- `POST /agent-auth/revoke` — agent self-revokes (`self:revoke` scope).
- Admin runbook RB-2 (`scripts/post-promotion-reset.sh` and the runbook docs) — operator-driven cascade revoke for compromised keys.

## How fast is validation?

`validation_cache_hit` P99 = **3.2 µs** (in-process LRU + bounded staleness).
`validation_cache_miss + HMAC` P99 = **6.5 µs** (Postgres lookup + KMS pepper HMAC).

Targets per SPEC §12.6 are 50 ms / 100 ms — we're orders of magnitude under.

## Does Vouch support multi-tenant?

Yes — `req.agent.account_id` is enforced by construction. Every query you write should scope by `account_id` (RT-9). The lib's own queries already do.

## Why HMAC + KMS pepper instead of Argon2id?

ADR-003 covers this. Short version: Argon2id is appropriate for human passwords (high entropy, low-throughput verification). API keys are 256-bit random — there's no value in slow hashing, and we want sub-10 µs verification on the hot path. HMAC + KMS-held pepper gives us:
- Database leak alone doesn't reveal keys (pepper is in KMS, not the DB).
- Pepper rotation is a key rotation policy, not a re-hash-everything migration.
- Consistent verification cost regardless of key strength.

## Does the lib include a dashboard?

No. The CLI ships runbooks (`@vouch/cli` v0.2 will add `vouch admin <runbook>`); a web admin dashboard is part of [Vouch Cloud](https://github.com/shizhigu/agent-auth#roadmap) (v1.0).

## Can I use Vouch on Cloudflare Workers / Bun / Deno?

Yes for the [Hono adapter](/) — the validate-key middleware and lifecycle routes work in any V8/JSCore-style runtime that supports the standard `fetch`, `crypto.subtle`, and `URL` APIs. Postgres + Redis access requires a TCP-capable runtime (Node, Bun) or a service-binding (Hyperdrive on Workers, Upstash for Redis).

## How do I report a security issue?

See [SECURITY.md](https://github.com/shizhigu/agent-auth/blob/main/SECURITY.md). TL;DR: open a private GitHub Security Advisory; do not file a public issue.

## What's the license?

MIT. The OSS core is fully usable + forkable + commercial-friendly. Vouch Cloud (v1.0) will be a managed hosted service alongside the OSS, not a closed-source rewrite.
