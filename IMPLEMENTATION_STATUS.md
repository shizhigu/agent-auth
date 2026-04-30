# IMPLEMENTATION_STATUS

Source of truth: SPEC.md §11.2 build order. Each subtask cites the SPEC sections it
implements. Marked `[x]` when both production code AND its tests pass.

When a subtask deviates from SPEC.md, an ADR is required in Appendix B (§ADR-N).

Legend: `[ ]` pending · `[~]` in progress · `[x]` done · `[blocked]` see notes.

## Milestone M1 — Core data model + validation (SPEC §11.2 M1)

- [x] Project scaffolding: `package.json`, `tsconfig.json` (strict), vitest, ESLint, `.gitignore`
- [x] Postgres schema migrations (full DDL) — §3.3-3.16
  - [x] `0001_init.sql` — type domains, roles, accounts, identities, api_keys, jobs, registration_sessions, device_flows + triggers (rotation_inverse, sync_account_tier_to_keys)
  - [x] `0002_audit.sql` — `agent_audit_log` partitioned + hash chain trigger §3.8 + `agent_webhook_events` §3.9 + `agent_webhook_replay_state` §3.10 + `agent_audit_outbox` §6.4.2
  - [x] `0003_revocation.sql` — `agent_revocation_log`, `agent_revocation_epoch` (epoch monotonic trigger), `agent_revocation_barrier` (barrier+timeline monotonic trigger), `agent_recovery_approvals` §3.11-3.14
  - [x] `0004_idempotency.sql` — `agent_idempotency` + transition trigger + terminal-row-immutable trigger §3.13
- [x] `src/types.ts` — shared TypeScript domain types (tier, statuses, KeyCache, AgentContext, IdentityProvider, etc.)
- [x] `src/errors.ts` — `AgentAuthError` class, `ServiceUnavailableError`, error code enum §10.4
- [x] `src/agent-context.ts` — frozen `AgentContext` builder, no `req.user` (§6.3 confused-deputy)
- [x] `src/storage/postgres-adapter.ts` — pg Pool wrapper with role-aware connections + transaction helper (§3.16)
- [x] `src/storage/redis-adapter.ts` — ioredis wrapper, Lua script loader (epoch MAX), pubsub patterns; InMemoryRedisAdapter for tests
- [x] `src/storage/kms-adapter.ts` — AWS KMS wrapper (envelope encrypt/decrypt) + InMemoryKmsAdapter for tests, dual-pepper §6.1.2
- [x] `src/crypto/hmac-pepper.ts` — HMAC-SHA256 with KMS-held pepper, dual-pepper rotation, constant-time-stable verification §6.1.1
- [x] `src/crypto/audit-hash.ts` — canonicalAuditText + computeRowHash + verifyChain (mirrors §3.8 trigger)
- [x] `src/crypto/pkce.ts` — generatePkcePair + deriveChallenge (RFC 7636 §4.1, S256)
- [x] `src/middleware/validate-key.ts` — full validation flow §5.3.3 (local → Redis → Postgres, epoch invalidation, dual-pepper HMAC)
- [x] `src/middleware/express-adapter.ts` + `src/middleware/hono-adapter.ts` — bearer extraction, X-Request-Id, onAccept/onReject hooks, docs_url_base, structured error mapping
- [x] `src/cache/local-cache.ts` — LRU 1000 + 30 s TTL + injectable clock §5.3.1
- [x] `src/config.ts` — `AgentAuthConfig` type + `resolveConfig()` defaults §11.4
- [x] Unit tests for: validation flow, agent-context immutability, error mapping, hmac-pepper dual-window, hash chain canonicalization, LRU/TTL cache, Redis epoch monotonicity, PKCE S256 (RFC 7636 vector), Express + Hono middleware end-to-end (94 unit tests, all green)
- [x] **Deliverable**: SaaS can mount middleware and validate manually-inserted keys (per §11.2 M1)

## Milestone M2 — GitHub App registration (SPEC §11.2 M2)

- [x] `src/identity/provider.ts` — `IdentityProvider` interface §2.1 (lives in `src/types.ts`)
- [x] `src/identity/github-app/browser-flow.ts` — `GitHubAppProvider`: authorize URL builder, code-exchange via `fetch` (injectable), Attestation construction, App-JWT-based revalidate fallback §2.2.2
- [ ] `src/identity/github-app/device-flow.ts` — alt path §2.2.3 (deferred — v0.1 default is browser flow per §2.2.1)
- [x] `src/identity/github-app/revalidate.ts` — folded into `GitHubAppProvider.revalidate()` (no-op when no app private key configured)
- [x] `src/routes/begin-registration.ts` — zod input validation, PKCE+nonce mint, session insert, IdP `beginRegistration` call, 503 idp_circuit_open on provider error §10.1
- [x] `src/routes/registration-status.ts` — pending/completed/failed state machine + RT-21 cross-kind rejection §10.1
- [x] `src/routes/callback.ts` — full §2.2.2 step a-k pipeline: nonce-bound session FOR UPDATE, exchanging→ready transitions, audience-binding check, identity cases A/B/C/D, account+identity creation, key issuance, sealed-box payload write
- [x] `src/identity/issue-key.ts` — shared `issueNewKey(client, kms, input)` + `buildSealedPayload` (§2.2.2 step h, §2.6); reused by /rotate-key in M3
- [x] `src/crypto/sealed-box.ts` — libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305), 48 bytes overhead, async-init guard §2.6 / ADR-004
- [x] `src/jobs/reaper.ts` — `reapRegistrationSessions` deletes sessions 1h past `expires_at` §3.6
- [x] PKCE state binding + nonce single-use enforced via `agent_registration_sessions` schema (`nonce UNIQUE`, FOR UPDATE in callback) §2.2.2 / §6.2.1 RT-29
- [ ] **Integration test**: full GitHub App registration end-to-end (RT-29, RT-31)
- [ ] **Deliverable**: SaaS can let agents register accounts via GitHub OAuth

## Milestone M3 — Rotation + Revocation + Idempotency (SPEC §11.2 M3)

- [ ] `src/routes/rotate-key.ts` — planned grace + emergency §2.7
- [ ] `src/routes/revoke.ts` §2.8
- [x] `src/distributed/revocation-epoch.ts` — `bumpEpochInTx(client, redis)` advances Postgres singleton + pushes via Redis Lua MAX §5.3.2
- [x] `src/distributed/revocation-barrier.ts` — `captureBarrierAfterCommit` reads `pg_current_wal_insert_lsn()` + advances barrier; `readAuthoritativeBarrier` for secondary regions §4.4.2
- [x] `src/distributed/tier-b-commit.ts` — `tierBCommit` race + Postgres XX098 detection; `tierBTransaction` sets `synchronous_commit='remote_apply'` §4.3
- [x] `src/reliability/idempotency.ts` — `tierBIdempotent` two-phase reservation; `canonicalRequestHash` deep-sort SHA-256 §5.1.1
- [ ] `src/middleware/idempotency.ts` — wrap mutation routes (deferred: routes call `tierBIdempotent` directly in M3)
- [x] `src/jobs/reconcile-idempotency.ts` — observer with 5 attempts / 30 min cap, page-on-call hook, committed/not_found/indeterminate handling §5.1.2
- [x] Cache invalidation pipeline — `src/distributed/cache-invalidation.ts` with `invalidateKey` (DEL + PUBLISH) and `invalidateAccountKeys` (Postgres-authoritative walk + per-key invalidation) §5.3.4 / §5.3.5
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

- **2026-04-30 (M3)**: Resolved internal SPEC tension between §4.3 (tierBCommit converts TierBTimeoutError → ServiceUnavailableError) and §5.1.1 (tierBIdempotent's `catch (err) { if (err instanceof TierBTimeoutError)` block expected the raw class). Picked `tierBCommit` as the sole converter and added **ADR-014** in Appendix B. `tierBIdempotent` now catches the converted ServiceUnavailableError(durability_unconfirmed | durability_unavailable), persists `state='unknown'`, and re-throws `ServiceUnavailableError(idempotency_unknown_outcome)`. Net effect on caller contract is identical (still 503), but only this composition produces a deterministic outcome regardless of which clause "wins".
