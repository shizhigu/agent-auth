---
layout: home

hero:
  name: Vouch
  text: Identity infrastructure for AI agents
  tagline: Drop it next to your existing human auth — never replaces it. Open-source today. Cloud coming.
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/shizhigu/agent-auth

features:
  - title: 15-line drop-in
    details: One `vouch()` call builds Postgres, Redis, KMS adapters and wires the 12 lifecycle routes. Express + Hono adapters bundled.
  - title: Sealed-box key delivery
    details: libsodium `crypto_box_seal` gates the bearer token to the agent's pubkey. Stolen poll tokens cannot extract the key.
  - title: Postgres-authoritative
    details: Strong consistency for state, Redis as a 30-second-bounded cache. Correctness never depends on Redis alone (RT-3, RT-26).
  - title: Append-only audit chain
    details: Postgres trigger derives `prev_hash`/`row_hash`; hourly verifier walks the chain; WORM mirror in S3 Object Lock for SOC 2 / GDPR.
  - title: Multi-region active-passive
    details: LSN barrier + timeline-aware revocation. Failover playbook (RB-8) included; chaos-tested in CI.
  - title: 32 of 44 RT-* threats covered with tests
    details: Unit + integration + chaos + property-based suites enforce the threat model. Audit trail says everything else is operational.
  - title: Drop-in scaffolder
    details: <code>npx create-vouch-app my-saas</code> writes a working Express SaaS template; <code>--template agent</code> writes a Node agent.
  - title: First-class CLI
    details: <code>vouch migrate up</code> applies, rolls back, and tracks SQL migrations in a transactional <code>vouch_migrations</code> table.
---

## Quick start

```bash
npx create-vouch-app my-saas
cd my-saas
cp .env.example .env
docker compose up -d
npx vouch migrate up
npm install
npm run dev
```

For the full walkthrough, see [Getting started →](/getting-started)

## What's it not?

Vouch is **complementary** to existing auth tools, not a competitor.

- **Better Auth · Auth0 · Clerk · Lucia** → "humans log into your SaaS"
- **Nango · Arcade · Auth0 for AI Agents** → "your code calls third-party APIs (Slack, GDrive, …) on behalf of an authenticated human"
- **Vouch** → "AI agents register accounts on YOUR SaaS and get their own scoped API keys"

If you're building Acme SaaS and want Claude Code / Cursor / Codex to autonomously sign up for an Acme account on a human's behalf and call the Acme API: **Vouch fills that gap**. None of the others do.
