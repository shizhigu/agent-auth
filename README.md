# agent-auth

Production-grade auth rail for AI agents. Sits next to existing human auth, never replaces it.

## What this is

A library that a SaaS provider drops into their backend so AI agents (Claude Code, Cursor, etc.) can register accounts on behalf of human users programmatically and obtain scoped API keys. Solves the "agents can't autonomously sign up because of CAPTCHA / email verification" problem without requiring SaaS providers to redesign their existing human auth flows.

## What this is not

- Replacement for Clerk / Auth0 / Better Auth (those handle human auth; we handle agent auth)
- Browser automation (Browserbase / Skyvern do that; this is a SaaS-side library)
- Agent identity / governance platform (Microsoft Agent Governance Toolkit does that)
- Token vault for already-authorized SaaS APIs (Nango / Arcade / Auth0-for-AI-Agents do that)
- Marketplace / payment for agents (Orthogonal does that)

## Status

**v0.1 implementation complete.** All 8 milestones (M1-M8) delivered;
v0.1.1 deployment-gated items enumerated in `docs/PRE_RELEASE_CHECKLIST.md`.

**Test coverage at HEAD** (see `IMPLEMENTATION_STATUS.md` for the full breakdown):

| Tier | Count | Wall | Notes |
|---|---|---|---|
| Unit (vitest) | 262 | ~0.9 s | includes fast-check property sweeps |
| Integration (testcontainers Postgres + Redis) | 32 | ~35 s | real DB + trigger invariants |
| Chaos (testcontainers + injected faults) | 14 | ~10 s | RT-15/18/22/25/32/34/43 |
| Bench (vitest bench) | 2 | 5 s | cache-hit P99 ≈ 4 µs, miss+HMAC P99 ≈ 9 µs (§12.6 target 50/100 ms) |

33 of 44 RT-* threats have automated test coverage; the remaining 11 are
out-of-band SaaS-side / agent-SDK responsibilities or acknowledged
compromises per SPEC §6.2.7.

The specification has been audited across 13 rounds with codex (GPT-5).
Final grade: **A spec / production-ready paying-customer design level**.
A+ is unattainable in spec form alone (requires deployed controls +
tested failover + completed SOC 2 audit + customer reference deployments).

## Tech stack (one-liner)

**Node.js 20+ (Bun-compatible), TypeScript 5.4 strict, libsodium + pg + ioredis + AWS SDK v3 (KMS/S3) + zod + pino, vitest + testcontainers + fast-check.** Framework-agnostic with optional adapters for Express / Hono / Fastify / Next.js. Full breakdown in `SPEC.md` Part XI §11.3.

## Repository layout

```
.
├── README.md                  ← you are here
├── SPEC.md                    ← THE comprehensive specification (start here for implementation)
├── audit/                     ← 13 rounds of codex audit history (preserves design rationale)
│   ├── round-1-prompt.md      ← initial design audit prompt
│   ├── round-2-prompt.md      ← solution audit prompt
│   ├── round-2-v3.md          ← v3 base spec (post-round-2 audit)
│   ├── round-3-v4.md          ← v4 patch (post-round-3 audit, 5 critical findings closed)
│   ├── round-4-v5.md          ← v5 patch (round-4 4 must-fixes)
│   ├── round-5-v6.md          ← v6 patch (round-5 high-risk findings)
│   ├── round-6-v7.md          ← v7 patch (production-grade additions)
│   ├── round-7-v8.md          ← v8 patch (5 must-fixes for paying-customer level)
│   ├── round-8-v9.md          ← v9 patch (9 A-blockers closed)
│   ├── round-9-v10.md         ← v10 patch (round-9 7 A-blockers + 9 threats)
│   ├── round-10-v11.md        ← v11 patch (round-10 4 blockers + revalidation UX)
│   ├── round-11-v12.md        ← v12 narrow patch (10 round-11 items)
│   ├── round-12-v13.md        ← v13 final patch (1 must-fix: barrier source)
│   └── round-13-v14.md        ← v14 micro-edit (cache semantics + LSN provenance)
├── schema/                    ← SQL DDL files (extracted from SPEC.md, runnable)
├── examples/                  ← reference implementations of key flows
└── docs/                      ← supplementary docs (runbooks, ADRs, GDPR templates)
```

## How to read this

1. **Reading order for implementation**: SPEC.md (top to bottom) → schema/ → examples/
2. **Reading order for design rationale**: audit/ in numeric order (preserves the 13-round design evolution and why each decision was made)
3. **Reading order for security review**: SPEC.md Part VI (Threat Model) + Part IX (Compliance) + audit/round-{12,13} (final security audits)

## Implementation expectations

Per codex round-13 verdict ("Stop iterating. Yes."): the spec is at the design ceiling. Next value comes from implementation tests, not more spec rounds. Specifically:

- Stale replica scenarios (LSN barrier correctness)
- Post-revoke validation (Tier B durability)
- Failover timeline mismatch (operator intervention)
- Admin override audit (cannot bypass without DB role)
- Idempotency transition violations (state machine)
- Concurrent rotation race (UNIQUE indexes + trigger)
- Webhook signature canonicalization (HMAC over canonical form)
- Sealed-box decrypt failures (bounded retry + cleanup)
- Cross-region barrier reads (authoritative source)

Each of these has explicit test specifications in SPEC.md Part XI (Testing Strategy).

## Estimated implementation effort

Per codex round-6 estimate, assuming AI-agent coding (Claude Code / Cursor / Codex):
- v0.1 disciplined cut: 2-3 weekends
- v0.2 with all production-grade items: 4-6 weekends
- Full v1.0 spec compliance: 8-12 weekends total + integration tests

Per codex round-13: implementation tests are the next critical investment, not more spec rounds.

## License

MIT (planned).

## Author

Shizhi Gu · github.com/shizhigu · szgu.dev
