# IMPLEMENTATION_STATUS

Source of truth: SPEC.md §11.2 build order. Each subtask cites the SPEC sections it
implements. Marked `[x]` when both production code AND its tests pass.

When a subtask deviates from SPEC.md, an ADR is required in Appendix B (§ADR-N).

Legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[blocked]` see notes.

## Milestone M1 — Core data model + validation (SPEC §11.2 M1)

- [x] Project scaffolding: `package.json`, `tsconfig.json` (strict), vitest, ESLint, `.gitignore`
- [ ] Postgres schema migrations (full DDL) — §3.3-3.16
  - [ ] `0001_init.sql` — type domains, accounts, identities, api_keys, sessions, device_flows
  - [ ] `0002_audit_partitions.sql` — `agent_audit_log` partitioned + hash chain trigger §3.8
  - [ ] `0003_idempotency.sql` — `agent_idempotency` + transition trigger §3.13
  - [ ] `0004_revocation.sql` — `agent_revocation_log`, `agent_revocation_epoch`, `agent_revocation_barrier`, `agent_recovery_approvals` §3.11-3.14
  - [ ] `0005_jobs.sql` — `agent_jobs`, `agent_audit_outbox`, `agent_webhook_events`, `agent_webhook_replay_state` §3.9-3.10, §3.15
- [x] `src/types.ts` — shared TypeScript domain types (tier, statuses, KeyCache, AgentContext, IdentityProvider, etc.)
- [x] `src/errors.ts` — `AgentAuthError` class, `ServiceUnavailableError`, error code enum §10.4
- [x] `src/agent-context.ts` — frozen `AgentContext` builder, no `req.user` (§6.3 confused-deputy)
- [ ] `src/storage/postgres-adapter.ts` — pg Pool wrapper with role-aware connections (§3.16)
- [ ] `src/storage/redis-adapter.ts` — ioredis wrapper, Lua script loader, pubsub
- [ ] `src/storage/kms-adapter.ts` — AWS KMS wrapper (encrypt/decrypt, dual-pepper) §6.1.2
- [ ] `src/crypto/hmac-pepper.ts` — HMAC-SHA256 with KMS-held pepper, dual-pepper rotation §6.1.1
- [ ] `src/crypto/audit-hash.ts` — SHA-256 over canonical JSON (mirrors §3.8 trigger)
- [ ] `src/crypto/pkce.ts` — PKCE S256 helpers
- [ ] `src/middleware/validate-key.ts` — main validation flow (Redis → Postgres) §5.3.3
- [ ] `src/middleware/express-adapter.ts` + `src/middleware/hono-adapter.ts`
- [ ] `src/cache/local-cache.ts` — in-memory LRU 1000, 30 s TTL §5.3.1
- [ ] `src/config.ts` — `AgentAuthConfig` type + defaults §11.4
- [ ] Unit tests for: validation flow, agent-context immutability, error mapping, hmac-pepper dual-window, hash chain canonicalization
- [ ] **Deliverable**: SaaS can mount middleware and validate manually-inserted keys (per §11.2 M1)

## Milestone M2 — GitHub App registration (SPEC §11.2 M2)

- [ ] `src/identity/provider.ts` — `IdentityProvider` interface §2.1
- [ ] `src/identity/github-app/browser-flow.ts` — beginRegistration, exchangeOrVerify §2.2.2
- [ ] `src/identity/github-app/device-flow.ts` — alt path §2.2.3
- [ ] `src/identity/github-app/revalidate.ts` — periodic re-verification §2.4
- [ ] `src/routes/begin-registration.ts` §10.1
- [ ] `src/routes/registration-status.ts` §10.1
- [ ] `src/routes/callback.ts` — OAuth code → attestation → key issuance §2.2.2
- [ ] `src/crypto/sealed-box.ts` — libsodium `crypto_box_seal` §2.6
- [ ] `src/jobs/reaper.ts` — expire registration sessions §3.6
- [ ] PKCE state binding + nonce single-use §2.2.2 / §6.2.1 RT-29
- [ ] **Integration test**: full GitHub App registration end-to-end (RT-29, RT-31)
- [ ] **Deliverable**: SaaS can let agents register accounts via GitHub OAuth

## Milestone M3 — Rotation + Revocation + Idempotency (SPEC §11.2 M3)

- [ ] `src/routes/rotate-key.ts` — planned grace + emergency §2.7
- [ ] `src/routes/revoke.ts` §2.8
- [ ] `src/distributed/revocation-epoch.ts` — epoch bump + Redis Lua MAX §5.3.2
- [ ] `src/distributed/revocation-barrier.ts` — post-commit LSN capture §4.4.2
- [ ] `src/distributed/tier-b-commit.ts` — synchronous_commit wrapper, timeout handling §4.3
- [ ] `src/reliability/idempotency.ts` — two-phase reservation + observer §5.1.1, §5.1.2
- [ ] `src/middleware/idempotency.ts` — wrap mutation routes
- [ ] `src/jobs/reconcile-idempotency.ts` — unknown→completed/failed/manual_required observer §5.1.2
- [ ] Cache invalidation pipeline (DEL + PUBLISH) §5.3.4
- [ ] Integration tests: post-revoke validation (RT-26), idempotency replay mismatch (RT-27), concurrent rotation race
- [ ] **Deliverable**: rotation/revocation atomic; observer reconciles unknowns

## Milestone M4 — Webhooks + reconciliation (SPEC §11.2 M4)

- [ ] `src/routes/webhooks.ts` — HMAC verify FIRST, dedup INSERT §2.2.4
- [ ] `src/identity/github-app/webhook.ts` — GitHub-specific event parsing §2.2.4
- [ ] `src/jobs/webhook-replay.ts` — 3-day GitHub redelivery polling §2.2.5
- [ ] Cascade identity-revoke → key-revoke pipeline §2.2.4
- [ ] Integration tests: RT-6 (replay), RT-30 (spoof / order gap), RT-42 (secret rotation race)
- [ ] **Deliverable**: GitHub revocations reach our system

## Milestone M5 — Rate limiting + observability (SPEC §11.2 M5)

- [ ] `src/reliability/gcra.ts` + Lua script §5.2.1
- [ ] `src/middleware/rate-limit.ts` — multi-dimensional limits §5.2.2
- [ ] `src/observability/metrics.ts` — Prometheus exposition §7.1
- [ ] `src/observability/logging.ts` — structured + scrubber §7.2 / §6.6
- [ ] `src/observability/tracing.ts` — OTel spans (with attr scrubber RT-44) §7.3
- [ ] `src/reliability/circuit-breaker.ts` — upstream IdP §5.4
- [ ] Integration tests: RT-15 (DoS), RT-43 (fail-closed amplification), RT-44 (APM leakage)
- [ ] **Deliverable**: production-grade observability + abuse protection

## Milestone M6 — Recovery + multi-region (SPEC §11.2 M6)

- [ ] `src/routes/recover-account.ts` + `recover-account-confirm` §2.9
- [ ] `src/routes/recover-account-status.ts`
- [ ] Recovery state machine (active-only invariant) §2.9
- [ ] Owner-approval webhook signing §2.9 / RT-19, RT-41
- [ ] LSN barrier protocol — post-commit capture, cross-region read §4.4.2
- [ ] Cross-region validation — authoritative barrier on primary §4.4.3
- [ ] `scripts/post-promotion-reset.sh` — failover readiness gate §4.4.4
- [ ] Integration tests: stale replica scenario, cross-region barrier, failover timeline mismatch (RT-18, RT-32, RT-34)
- [ ] **Deliverable**: multi-region active-passive with correct revocation visibility

## Milestone M7 — Audit + compliance (SPEC §11.2 M7)

- [ ] `src/audit/db-writer.ts` — in-DB hash chain insert §6.4.1
- [ ] `src/audit/worm-writer.ts` — S3 Object Lock COMPLIANCE writer §6.4.2
- [ ] `src/audit/scrubber.ts` — allow-list + entropy detection §6.6
- [ ] `src/audit/verify-chain.ts` — hourly tamper detection job §6.4.1
- [ ] `src/jobs/outbox-flusher.ts` — outbox → WORM retry §6.4.2
- [ ] `src/jobs/audit-verifier.ts` — hash chain check
- [ ] `scripts/dr-drill.sh` — quarterly DR drill §8.3.3
- [ ] Integration tests: tamper detection (RT-12), audit omission (RT-39), WORM suppression (RT-28)
- [ ] **Deliverable**: SOC 2 / GDPR ready audit trail

## Milestone M8 — Admin CLI + supply chain (SPEC §11.2 M8)

- [ ] `src/admin/cli.ts` — base command framework §8.1
- [ ] RB-1 .. RB-9 command implementations §8.2
- [ ] `src/admin/webauthn.ts` — FIDO2 hardware key gating §8.1
- [ ] `src/admin/two-person.ts` — co-signer enforcement §8.1
- [ ] `src/admin/jit-rbac.ts` — just-in-time role grant
- [ ] `.github/workflows/release.yml` — Sigstore signing + npm provenance §9.3
- [ ] OIDC trusted publishing setup §9.3 / RT-14, RT-36
- [ ] Integration tests: RT-10 (admin abuse), RT-38 (SSO compromise → break-glass)
- [ ] **Deliverable**: production-ready release pipeline

## Cross-cutting / pre-release (SPEC §12.7)

- [ ] All 44 RT-* threats have integration tests §12.3
- [ ] Chaos tests pass (Toxiproxy) §12.4
- [ ] Property-based tests pass (idempotency, rotation, audit chain) §12.5
- [ ] `npm run bench` within targets §12.6
- [ ] Pre-release checklist §12.7 fully green
- [ ] Threat-mitigation matrix audit fresh (each RT-N → test cite)

## Notes / deviations / blockers

(Populate as iterations progress. Keep entries dated.)
