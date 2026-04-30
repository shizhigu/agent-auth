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
- [x] **Integration test**: full GitHub App registration end-to-end (RT-29, RT-31) — `test/integration/registration.int.test.ts` (4 tests): happy path through callback + sealed-payload decrypt + `validateKey` round-trip; RT-29 single-use nonce replay; RT-31 audience-mismatch (lying provider) and RT-31 cross-tenant recovery (`identity_account_mismatch`)
- [x] **Deliverable**: SaaS can let agents register accounts via GitHub OAuth

## Milestone M3 — Rotation + Revocation + Idempotency (SPEC §11.2 M3)

- [x] `src/routes/rotate-key.ts` — planned (Tier A, grace seconds → rotating + grace_expires_at) and emergency (Tier B inside `tierBIdempotent`, grace=0 → revoked); calls `issueNewKey` for the successor; `bumpEpochInTx` (rotating is auth-relevant); optional sealed-box delivery via `client_pubkey_b64` §2.7
- [x] `src/routes/revoke.ts` — Tier B inside `tierBIdempotent`; bumps epoch + appends revocation_log + updates per-key `last_revoke_lsn`; post-commit barrier capture + `invalidateKey`; scope check (`self:revoke` for own key, `admin:keys` for others on same account); 404 anti-enumeration §2.8
- [x] `src/routes/list-keys.ts` — GET /api/agent-auth/keys (§10.1) — admin:keys-scoped projection of caller's account keys; revoked rows excluded; cross-account guard; integration + unit covered
- [x] `src/routes/healthz.ts` — GET /api/agent-auth/healthz (§10.2) — reads authoritative barrier (timeline_id + last_lsn) + redis epoch; surfaces circuit-breaker states; 200 healthy / 503 unhealthy with `reasons[]` (postgres_unreachable, redis_unreachable, circuit_breaker_open:&lt;name&gt;)
- [x] `src/routes/well-known.ts` — GET /.well-known/agent-auth (§10.1) — service discovery body composer; honors per-provider capability overrides; ValidationMode → `barrier_mode` string ('strict_uncached' or `bounded_stale_<n>s`); strips trailing slash from base_url
- [x] `src/distributed/revocation-epoch.ts` — `bumpEpochInTx(client, redis)` advances Postgres singleton + pushes via Redis Lua MAX §5.3.2
- [x] `src/distributed/revocation-barrier.ts` — `captureBarrierAfterCommit` reads `pg_current_wal_insert_lsn()` + advances barrier; `readAuthoritativeBarrier` for secondary regions §4.4.2
- [x] `src/distributed/tier-b-commit.ts` — `tierBCommit` race + Postgres XX098 detection; `tierBTransaction` sets `synchronous_commit='remote_apply'` §4.3
- [x] `src/reliability/idempotency.ts` — `tierBIdempotent` two-phase reservation; `canonicalRequestHash` deep-sort SHA-256 §5.1.1
- [ ] `src/middleware/idempotency.ts` — wrap mutation routes (deferred: routes call `tierBIdempotent` directly in M3)
- [x] `src/jobs/reconcile-idempotency.ts` — observer with 5 attempts / 30 min cap, page-on-call hook, committed/not_found/indeterminate handling §5.1.2
- [x] Cache invalidation pipeline — `src/distributed/cache-invalidation.ts` with `invalidateKey` (DEL + PUBLISH) and `invalidateAccountKeys` (Postgres-authoritative walk + per-key invalidation) §5.3.4 / §5.3.5
- [x] Integration tests: post-revoke validation (RT-26 in `validate-key.int.test.ts`), idempotency replay mismatch (RT-27 in `idempotency.int.test.ts`), concurrent rotation race (`§3.5` trigger in `rotation.int.test.ts`)
- [x] **Deliverable**: rotation/revocation atomic; observer reconciles unknowns

## Milestone M4 — Webhooks + reconciliation (SPEC §11.2 M4)

- [x] `src/routes/webhooks.ts` — framework-agnostic; HMAC verify FIRST (delegated to provider), atomic dedup `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING (xmax=0)`, applies actions in Tier B txn, post-commit barrier + `invalidateKey` walk §2.2.4
- [x] `src/identity/github-app/webhook.ts` — implemented as `GitHubAppProvider.handleWebhook` (constant-time HMAC, dual-secret rotation per RT-42, JSON parse, `revoke_identity` action for `github_app_authorization` action='revoked') §2.2.4
- [x] `src/jobs/webhook-replay.ts` — `runWebhookReplay(deps)` paginates `/app/hook/deliveries`, skips delivered (2xx) and processed locally, triggers redelivery, updates `agent_webhook_replay_state` cursor + status + cap_hit metric §2.2.5
- [x] Cascade identity-revoke → key-revoke pipeline (revoked identity ⇒ all active+rotating keys ⇒ epoch + log + cache invalidate; account suspended if no other primary identity remains) §2.2.4
- [x] Integration tests: RT-6 (replay), RT-30 (spoof / order gap), RT-42 (secret rotation race) — `webhook.int.test.ts` (6 tests): RT-6 replay returns 'duplicate'; RT-30 collision raises onAlert with `webhook_id_collision_with_payload_mismatch`; RT-42 dual-secret window accepts deliveries signed with `webhook_secret_previous` AND with current secret; RT-42 closed window (no `webhook_secret_previous`) rejects old-secret deliveries 401
- [x] **Deliverable**: GitHub revocations reach our system (route + provider + cascade + replay job)

## Milestone M5 — Rate limiting + observability (SPEC §11.2 M5)

- [x] `src/reliability/gcra.ts` — `gcraCheck` / `gcraEvaluate` / `gcraReject`; Lua script registered as `gcra` on the Redis adapter (and mirrored into `InMemoryRedisAdapter.evalSha`) §5.2.1
- [x] `src/middleware/rate-limit.ts` — `dim()` builder + `enforceRateLimits()` walks dimensions in order, throws 429 too_many_requests with `Retry-After` on first reject §5.2.2
- [x] `src/observability/metrics.ts` — `MetricsRegistry` with counter/gauge/histogram + Prometheus 0.0.4 text exposition; label values run through scrubber pre-emit (RT-44) §7.1
- [x] `src/observability/logging.ts` — `createLogger` emits structured JSON, runs message + meta through scrubber, supports minLevel + injectable `emit` §7.2
- [ ] `src/observability/tracing.ts` — OTel spans (deferred to M5 follow-up; scrubber + label guards already cover RT-44 surface area)
- [x] `src/observability/scrubber.ts` — value-pattern, key-name, high-entropy heuristics + length / depth / size caps §6.6 / RT-44
- [x] `src/reliability/circuit-breaker.ts` — closed/open/half-open state machine with rolling failure window, halfOpenAfter, halfOpenProbeCount, onOpen/onClose hooks; rejects with `idp_circuit_open` 503 §5.4
- [ ] Integration tests: RT-15 (DoS), RT-43 (fail-closed amplification), RT-44 (APM leakage) — covered by unit tests; full integration suite lands with M6 testcontainers
- [x] **Deliverable**: production-grade observability + abuse protection (scrubber, metrics, logger, GCRA + multi-dim middleware, circuit breaker)

## Milestone M6 — Recovery + multi-region (SPEC §11.2 M6)

- [x] `src/routes/recover-account.ts` — wraps `beginRegistration` with intent='recover', requires `account_id`, optional owner-approval webhook §2.9
- [x] `src/routes/recover-account-status.ts` — wraps `registrationStatus(endpoint='recover')` so cross-kind tokens (RT-21) reject 410 §10.1
- [x] `src/routes/recover-account-confirm.ts` — owner-approval receiver: HMAC verify (RT-19) + Redis SET-NX nonce single-use + agent_recovery_approvals state machine
- [x] Recovery state machine (active-only invariant) — enforced in /callback case C re-activation + RT-31 target_account_id guard §2.9
- [x] Owner-approval webhook signing — `src/identity/owner-approval-sign.ts` with canonical method+path+timestamp+nonce+request_id+body_hash HMAC, ±5 min skew, dual-direction (emit + verify) §2.9 / RT-19 / RT-41
- [x] LSN barrier protocol — post-commit capture in `captureBarrierAfterCommit`; revoke + emergency rotate + webhook cascade all advance the barrier §4.4.2
- [x] Cross-region validation — `src/distributed/multi-region-barrier.ts` exposes `makeBarrierCheck` that validateKey can plug into via `barrier_check`; reads authoritative barrier from primary, gates local replay LSN, throws 503 region_replication_stale or failover_in_progress §4.4.3
- [x] `scripts/post-promotion-reset.sh` — captures new LSN+timeline on freshly-promoted primary, advances barrier, FLUSHDBs Redis, emits promotion_completed audit event, touches readiness file §4.4.4
- [x] Integration tests: stale replica scenario, cross-region barrier, failover timeline mismatch (RT-18, RT-32, RT-34) — `test/integration/multi-region-barrier.int.test.ts` (7 tests) drives `makeBarrierCheck` against real authoritative barrier data with a thin local-side stub for `pg_is_in_recovery` / `pg_last_wal_replay_lsn` / `pg_control_checkpoint`
- [x] **Deliverable**: multi-region active-passive with correct revocation visibility (route + barrier + RB-8 script)

## Milestone M7 — Audit + compliance (SPEC §11.2 M7)

- [x] `src/audit/db-writer.ts` — `writeAuditRow` INSERT (trigger computes prev_hash + row_hash); meta scrubbed; `pseudonymizeIp` HMAC-SHA256(ip, internal_secret) helper §6.4.1 / §6.6; **`writeAuditRowOnClient(client, ...)`** in-tx variant for callers that need the audit row to commit atomically with their mutation
- [x] `src/audit/worm-writer.ts` — `writeAuditToWorm` PutObject with `ObjectLockMode='COMPLIANCE'` + 7-year retention; outbox enqueue on failure; `AwsS3WormPutter` (real) + `InMemoryWormPutter` (tests) §6.4.2 / ADR-010; tier='B' events fail-closed with 503 audit_unavailable when WORM put fails (RT-28 — outbox row still durable for retry)
- [x] **In-tx audit emission across all public Tier B routes** (SPEC §6.4) — /revoke, /rotate-key (planned + emergency), /webhooks/:provider cascade, /callback (registration + recover + revalidate success paths), /recover-account-confirm. Each writes `event_type=&lt;route&gt;` with account_id / key_id / identity_id and meta carrying the route-specific fields, all scrubbed by defaultScrubber.
- [x] `src/audit/scrubber.ts` — folded into `src/observability/scrubber.ts` (single scrubber serves audit + logs + metrics); applied automatically by `writeAuditRow` and `writeAuditToWorm` §6.6
- [x] `src/jobs/audit-verifier.ts` — daily-partition hash-chain integrity check via `verifyChain`; pages onAlert with `audit_hash_chain_break` + first break id/ts §6.4.1; accepts optional `target_day?: Date` for RB-6 forensic verification of a specific past day; query is bounded `[day_start, day_start+24h)` so cross-day rows can never splice into the inspected window
- [x] `src/jobs/outbox-flusher.ts` — drains `agent_audit_outbox` with retry budget; flags rows past `max_attempts` as `audit_outbox_stuck` for SREs §6.4.2
- [x] `src/jobs/audit-partition-manager.ts` — daily partition manager (SPEC §3.8 / §13.1.2). Pre-creates `agent_audit_log_YYYY_MM_DD` partitions for the next N days (default 7); idempotent skip when already attached. Migration 0002 sets parent OWNER to `agent_auth_migrator` so the job role can attach.
- [x] `scripts/dr-drill.sh` — quarterly DR drill: sample-prod-revoked → spot-check sandbox → assert audit chain present (§8.3.3)
- [x] Integration tests: tamper detection (RT-12), audit omission (RT-39), WORM suppression (RT-28) — RT-12 in `audit-chain.int` (admin-role tamper of row_hash flips first_break_index); RT-39 in `audit-outbox.int` (failed PutObject → outbox → flusher drains); RT-28 in `audit-outbox.int` (Tier B event with failing WORM put now throws `ServiceUnavailableError(audit_unavailable)` per §6.4.2 — closes a real implementation gap where the writer was never failing closed)
- [x] **Deliverable**: SOC 2 / GDPR-ready audit trail (in-DB chain + WORM mirror + outbox + verifier + DR drill)

## Milestone M8 — Admin CLI + supply chain (SPEC §11.2 M8)

- [x] `src/admin/cli.ts` — `runAdminCommand` dispatcher: JIT-RBAC check → WebAuthn (skipped on read-only) → two-person (when `TWO_PERSON_REQUIRED.has(command)`) → audit row → handler dispatch §8.1
- [x] RB-1..RB-7 + RB-9 command implementations in `src/admin/runbooks.ts` (RB-1 revoke-key, RB-2 suspend-account, RB-3 resolve-idempotency, RB-4 flush-cache, RB-5 unblock-identity, RB-7 reconcile-redis-sets, RB-9 webhook-backfill via existing `runWebhookReplay`); RB-8 already shipped as `scripts/post-promotion-reset.sh` §8.2
- [x] `src/admin/webauthn.ts` — `WebAuthnVerifier` interface + `noopWebAuthnVerifier` for tests; SaaS plugs in @simplewebauthn/server (or equivalent) for production (RT-10) §8.1
- [x] `src/admin/two-person.ts` — `createCoSignerEnvelope`, `signCoSignerEnvelope`, `verifyCoSignature` (canonical op+target+timestamp+nonce+initiator+payload_sha256, ±10 min skew, constant-time compare) §8.1 / RT-10 / RT-41
- [x] `src/admin/jit-rbac.ts` — `JitRbac` with grant/assertGrant/revoke; default 1h TTL, 4h cap; required reason ≥8 chars; audit hook on grant + revoke §8.1
- [x] `.github/workflows/release.yml` — npm `--provenance` + Sigstore (cosign sign-blob + SBOM) + `id-token: write` for OIDC trusted publishing per §9.3 / RT-14, RT-36
- [x] OIDC trusted publishing setup — workflow uses `id-token: write` permission; no `NPM_TOKEN`; `.npmrc` enables provenance globally §9.3
- [x] CI + Security workflows — `.github/workflows/ci.yml` (lint, typecheck, test) + `security.yml` (OpenSSF Scorecard, TruffleHog secret-scan, dependency-review on PRs) + CODEOWNERS + dependabot.yml
- [x] Integration tests: RT-10 (admin abuse), RT-38 (SSO compromise → break-glass) — RT-10 in `admin-cli.int` (RB-1 revoke-key end-to-end + RB-4 flush-cache rejected without co-signer / admitted with valid co-signer); RT-38 mitigation via `docs/break_glass.md` (per SPEC §8.1 break_glass.procedure reference) — independent break-glass admin path documented: physical YubiKeys + sealed-envelope JIT-RBAC seeds rooted independently of SSO, two-person co-sign required, audit `meta.break_glass=true` marker, 24h post-mortem mandate
- [x] **Deliverable**: production-ready release pipeline (Sigstore + provenance + Scorecard + CODEOWNERS + JIT-RBAC + two-person)

## Known gaps (deferred to v0.1.1)

- **§2.9 owner_approval doesn't actually gate /callback** —
  `emitOwnerApprovalRequest` (called from /recover-account) writes
  the agent_recovery_approvals row with decision='pending' and
  fires a signed webhook. /recover-account-confirm later updates
  the decision. But /callback for kind='recover' issues the new
  key without checking decision. SPEC §2.9 step 5–6: "Wait for
  approval ... After approval (or if not required) ... Issue NEW
  key". Effect: configured owner-approval webhooks notify the
  owner but don't actually gate recovery. Refactor scope: needs
  a session "awaiting_approval" status (or equivalent), key
  issuance deferred until approval, and a way for the deny path
  to revoke an already-issued key. SaaSes that don't configure
  owner_approval are unaffected. Tracked as deferred; no test
  exercises the gating today, so no integration regression.

## Cross-cutting / pre-release (SPEC §12.7)

- [~] **44 RT-* threats: 28 covered, 16 explicitly out-of-scope or
  operational §12.3** — unit + integration + chaos union covers
  RT-3, 6, 9, 10, 12, 15, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
  29, 30, 31, 32, 34, 39, 40, 41, 42, 43, 44. Gaps are (a) outside
  lib boundary (RT-7 process-memory key theft, RT-8 SDK leakage,
  RT-11 cross-tenant data leak in SaaS code), (b) operational /
  process (RT-1 supply-chain, RT-2 pinning, RT-4 backup, RT-13
  backup compromise, RT-14 SBOM, RT-16 cert pinning, RT-17 service
  account, RT-33 retention, RT-35 dependency typosquat, RT-36 npm
  publish chain, RT-37 KMS root rotation, RT-38 incident response
  drills) — none of which are unit-testable in this lib. RT-5 is
  reserved.
- [x] **Integration suite §12.3** — 23 suites, 87 tests passing
  via `npm run test:integration` against real Postgres 16 + Redis 7
  testcontainers. `test/integration/setup.ts` boots fixtures,
  applies migrations 0001..0005, exposes `IntegrationFixture`.
- [x] **Chaos tests pass §12.4** — 5 suites, 14 tests passing
  via `npm run test:chaos`:
  - `redis-partition.chaos.test.ts` (2): healthy-control + Redis
    stopped mid-flight, validateKey degrades safely (no false
    accept).
  - `multi-region-failover.chaos.test.ts` (3): timeline mismatch,
    LSN lag fail-closed / route-to-primary policies.
  - `kms-unavailable.chaos.test.ts` (3): pepper fetcher failure
    propagates as 503; legacy versions still accepted within
    dual-window even if current pepper unreachable.
  - `dos-rate-limit.chaos.test.ts` (3): GCRA rejects above
    burst budget; Redis-down behavior; multi-dim short-circuit.
  - `fail-closed-amplification.chaos.test.ts` (3): RT-43 circuit
    breaker on idp_circuit_open prevents fail-closed cascade.
  Toxiproxy is the SPEC reference implementation; we use direct
  testcontainers control (stop/start) which exercises the same
  failure modes more deterministically.
- [~] **Property-based tests pass §12.5** — fast-check covering
  idempotency state-machine transitions (`idempotency.property.test.ts`)
  and `canonicalRequestHash` (key-order invariance, array-order
  meaning, primitive type stability, deep equality). Rotation race
  + audit-canonical-bytes property tests deferred to v0.1.1.
- [x] **`npm run bench` within targets §12.6** — `bench/validation.bench.ts`:
  cache hit P99 ≈ 4 µs, cache-miss + HMAC P99 ≈ 9 µs (targets 50 ms / 100 ms).
- [x] **Pre-release checklist §12.7** — `docs/PRE_RELEASE_CHECKLIST.md`
  written; deferred items called out explicitly.
- [x] **Threat-mitigation matrix** — RT mapping in PRE_RELEASE_CHECKLIST.

## Test summary at HEAD

- **Unit tests**: 339 passing across 46 suites, ~930 ms wall (includes
  fast-check property tests + AwsKmsAdapter + AwsS3WormPutter via
  aws-sdk-client-mock + down-migration structural invariants).
- **Integration**: 91 passing against real Postgres 16 + Redis 7
  (testcontainers, ~80 s — healthz unhealthy-path waits ioredis retries):
  - validate-key.int (4): cache flow, RT-26 epoch invalidation, RT-3 redis
    fallback, invalid_secret rejection.
  - revoke.int (2): Tier B revoke writes log + bumps epoch + invalidates
    cache; idempotent replay no-ops.
  - webhook.int (6): cascade revoke (active + rotating keys + account
    suspension); RT-6 replay returns 'duplicate'; RT-30 collision raises
    onAlert; RT-42 dual-secret rotation window accepts both previous
    and current; RT-42 closed window (no webhook_secret_previous) rejects
    old-secret traffic 401; bad HMAC writes nothing to agent_webhook_events.
  - registration.int (4): full /begin → /callback → /status flow; sealed
    payload decrypts to validate-able key; RT-29 replay /callback rejected
    (single-use nonce); RT-31 audience-mismatch (lying provider) →
    audience_mismatch + zero rows minted; RT-31 cross-tenant recovery
    (target=B but identity belongs to A) → identity_account_mismatch +
    zero keys at B.
  - rotation.int (2): planned rotation transitions old → 'rotating' with
    grace + creates new active key; concurrent rotation race resolves via
    §3.5 unique_violation trigger.
  - audit-chain.int (4): hash chain intact for sequence of writeAuditRow
    calls; admin-role tamper of a row_hash flips first_break_index ≥ 0
    and pages oncall; cross-UTC-day independence — verifier with
    target_day=D treats each day's chain as ZERO_HASH-seeded, so a chain
    spanning two days verifies as two independent intact chains; UTC
    alignment under non-UTC session TIMEZONE — confirms 0005 trigger
    fix uses UTC for the per-day chain seed regardless of session TZ.
  - idempotency.int (5): tierBIdempotent end-to-end (pending →
    completed atomically); replay returns cached without re-running op;
    RT-27 payload-mismatch → 409; §3.13 trigger refuses pending →
    manual_required for app role; admin override allowed AND emits
    idempotency_admin_override audit event in the same txn; §3.13
    terminal-row immutability — request_hash cannot be UPDATEd after
    completed (errcode 23514).
  - postgres-adapter.int (5): SET ROLE pinning per checkout; transaction
    commit on success; transaction rollback on throw (intentional error
    leaves DB unchanged); statement_timeout cancels a long pg_sleep;
    queryOne throws on multi-row result.
  - distributed.int (5): §3.12 epoch monotonicity refuses non-strict
    UPDATE (errcode 23514); bumpEpochInTx increments Postgres + pushes
    to Redis; barrier same-timeline LSN regression refused; barrier
    timeline regression refused; barrier reset on new timeline allowed.
  - tombstone-reapply.int (1): RT-23/RT-40 — post-snapshot revocations
    captured in agent_revocation_log are reapplied to a "restored"
    cluster; reverted key flips back to revoked; second pass is a no-op
    (idempotent reapply); untouched keys stay active.
  - jobs.int (2): reapRegistrationSessions deletes 1h+old sessions
    (preserves fresh ones); reconcileAccountKeySets walks Postgres
    authoritative key list, SADDs missing entries, SREMs phantoms,
    excludes revoked keys.
  - audit-outbox.int (4): RT-39 — failed PutObject enqueues outbox row;
    flushAuditOutbox drains it on next pass; row past max_attempts is
    paged as 'audit_outbox_stuck' for ops; RT-28 — Tier B event with
    failing WORM put throws ServiceUnavailableError(audit_unavailable)
    AND outbox row still inserted for retry; Tier A default behavior
    is best-effort (returns outboxed without throwing).
  - webhook-replay.int (1): RT-6 / §2.2.5 — runWebhookReplay skips
    already-processed deliveries, wrong event types, 2xx-acked, and
    older-than-lookback; triggers redelivery only for the rest;
    advances the replay cursor.
  - rotate-key.int (2): emergency rotation flips old → revoked,
    issues a new key whose sealed-box payload decrypts to a key that
    validates; old bearer rejects 401 key_revoked; idempotent
    emergency replay returns the cached new_key (operation not re-run).
  - list-keys.int (3): GET /keys §10.1 — happy path returns active +
    rotating keys with §10.1 projection (revoked excluded); cross-
    account guard (caller from acct-A never sees acct-B keys);
    403 insufficient_scope when caller lacks admin:keys.
  - healthz.int (2): GET /healthz §10.2 — 200 healthy with timeline_id
    + barrier_lsn from the live singleton; 503 unhealthy with reasons
    including 'redis_unreachable' after testcontainers stop().
  - audit-partitions.int (3): SPEC §3.8 / §13.1.2 — manageAuditPartitions
    creates lookahead_days (3) daily partitions with deterministic
    YYYY_MM_DD names; rerun is idempotent (skipped); rows whose ts falls
    inside a created partition are routed to it (not the default catch-all).
  - recover-account.int (1): full §2.9 / §2.2.2 case-C flow against
    real DB. Webhook-revoked identity is re-activated, new key issued
    bound to the same account_id, sealed payload decrypts to a
    validate-able key; pre-revocation old key remains revoked (recover
    does NOT resurrect old keys per §2.9 step 6).
  - recover-account-confirm.int (4): RT-19 / RT-41 against real DB
    + Redis. Approve persists decision; replay with same nonce
    rejected (Redis SET NX guard); ts > 5 min skew rejected; idempotent
    decision — fresh-nonce replay against an already-decided row
    returns the cached decision unchanged.
  - admin-cli.int (2): RB-1 revoke-key end-to-end against real DB —
    audit row 'admin_revoke-key' written BEFORE side-effect; key
    revoked + epoch bumped + revocation_log appended; two-person
    flush-cache rejected without co-signer, succeeds with valid
    co-signer signature.
  - express-middleware.int (5): full HTTP round-trip against real DB
    via fetch — 200 happy path with req.agent + X-Request-Id echo;
    inbound X-Request-Id preserved verbatim; 401 invalid_key (no header)
    with documentation_url; 401 invalid_secret (tampered secret);
    403 insufficient_scope from route-thrown require_scope routed
    through SaaS error handler.
  - multi-region-barrier.int (7): `makeBarrierCheck` against real
    authoritative barrier (advanced via `captureBarrierAfterCommit`)
    with a thin local-side stub that only intercepts the three system
    function reads — primary short-circuit (in_recovery=false), healthy
    caught-up replica, replica ahead of barrier, RT-32 stale-replica +
    fail_closed → 503 region_replication_stale, RT-32 stale-replica +
    route_to_primary → RouteToPrimaryError, RT-34 timeline mismatch →
    503 failover_in_progress (priority over LSN), monotonic barrier
    advance after second WAL bump.
- **Chaos**: 14 passing (~10 s):
  - redis-partition (2): RT-25 healthy + partitioned-Redis no-false-accept
    invariant via testcontainers stop().
  - multi-region-failover (3): control passes when local IS the primary
    (recovery=false); RT-32 / RT-34 timeline mismatch → 503
    failover_in_progress; RT-18 replica behind authoritative barrier →
    503 region_replication_stale.
  - kms-unavailable (3): RT-22 control accepts with healthy KMS;
    KMS-down with correct OR wrong secret never silently accepts —
    validateKey surfaces an error path instead of returning AgentContext.
  - dos-rate-limit (3): RT-15 GCRA absorbs burst, rejects with bounded
    Retry-After ≤ period; per-IP dimension short-circuits over-rate
    without consulting other dims; 200 over-rate calls complete in <2 s
    (atomic Lua → no fan-out under attack).
  - fail-closed-amplification (3): RT-43 — circuit breaker opens after
    failureThreshold and operation invoked exactly that many times (no
    leak under flood); half-open admits exactly halfOpenProbeCount
    probes; 1000 concurrent calls while open never re-invoke the op.
- **Bench**: validation_cache_hit P50/P99 = 2.5 µs / 4.3 µs;
  validation_cache_miss_with_hmac P50/P99 = 5.0 µs / 8.9 µs.
- **Typecheck**: clean (`tsc --noEmit`).

## Notes / deviations / blockers

- **2026-04-30 (M3)**: Resolved internal SPEC tension between §4.3 (tierBCommit converts TierBTimeoutError → ServiceUnavailableError) and §5.1.1 (tierBIdempotent's `catch (err) { if (err instanceof TierBTimeoutError)` block expected the raw class). Picked `tierBCommit` as the sole converter and added **ADR-014** in Appendix B. `tierBIdempotent` now catches the converted ServiceUnavailableError(durability_unconfirmed | durability_unavailable), persists `state='unknown'`, and re-throws `ServiceUnavailableError(idempotency_unknown_outcome)`. Net effect on caller contract is identical (still 503), but only this composition produces a deterministic outcome regardless of which clause "wins".

- **2026-04-30 (M7)**: Audit verifier semantics. SPEC §6.4.1 verifier walks rows checking `prev_hash[i] == row_hash[i-1]` (linkage only). Earlier the TS `verifyChain` ALSO recomputed the row_hash from canonical bytes, but that requires reproducing Postgres's `jsonb_build_object(...)::text` output exactly — fragile because of timestamptz formatting and meta=NULL vs meta=undefined. Aligned to SPEC: hourly verifier uses `verifyChain` (linkage). The byte-level recompute lives in `verifyChainStrict`, used only by offline tamper-detection unit tests where canonical inputs are controlled. Real tamper detection in production: the §3.8 trigger on the next INSERT recomputes against the tampered row_hash, breaking the chain — `verifyChain` then catches the linkage break.

- **2026-04-30 (M7)**: Audit-log app-role grant. SPEC §3.16 wording was "GRANT SELECT, INSERT, UPDATE on ALL TABLES to agent_auth_app, then REVOKE UPDATE+DELETE on agent_audit_log". Equivalent end state: app role has SELECT + INSERT but no UPDATE/DELETE. Implemented as explicit `GRANT INSERT, SELECT ON agent_audit_log TO agent_auth_app` (instead of broad-grant + REVOKE), which is functionally identical and easier to read in 0002_audit.sql. Append-only invariant preserved.

- **2026-04-30 (post-v0.1 sweep)**: Correctness sweep on the implemented
  surface caught nine real bugs that escaped the v0.1 cut. Logged here
  for audit history; commits are linked in CHANGELOG. None were caught
  by the existing test suite — all required reading the SPEC alongside
  the implementation:
  1. **RT-28 / §6.4.2** — `writeAuditToWorm` silently returned
     `outboxed` for Tier B when S3 PutObject failed. Now throws
     `ServiceUnavailableError(audit_unavailable)`. Closed an evidence-
     suppression vector.
  2. **§5.1.3** — `tierBIdempotent` replay-of-failed always returned
     wire `code: 'invalid_request'` regardless of original error.
     Now preserves the original `code` + `message` + merges
     `details.replay = true`.
  3. **§10.5** — Hono adapter never set `X-Request-Id` on success
     responses (only on errors). Now uses Hono v4's `c.header()`
     after `next()`.
  4. **Testability** — `validateAgainstCache` ignored the injectable
     clock for `key_expired` / `rotation_grace_expired` checks, so
     fake-clock tests for those paths weren't deterministic. Threaded
     `now` through.
  5. **Testability** — `registrationStatus` and `recoverAccountStatus`
     used `Date.now()` directly for session-expiry checks. Both now
     accept injectable `now`.
  6. **Packaging** — `package.json` `exports` map didn't allow the
     deep imports the shipped examples use (e.g.,
     `agent-auth/identity/github-app/browser-flow.js`). First
     `npm install` would error out. Added wildcard subpaths.
  7. **§6.6 / RT-44 precision** — Scrubber converted `bigint` →
     `Number()` lossy (rounds past 2^53). Postgres BIGSERIAL IDs in
     audit meta would be silently corrupted. Now stringifies bigints.
  8. **§2.2.5 catch-up** — webhook-replay seeded the cursor with
     `last_seen_delivery_id`, but GitHub's pagination is reverse-
     chronological so cursor=X returns deliveries OLDER than X. Every
     run after the first SCANNED ALREADY-PROCESSED rows and silently
     skipped any new failed deliveries. Now uses the watermark as an
     inner-loop early-stop instead.
  9. **RT-19 atomicity** — `/recover-account-confirm` enforced webhook-
     nonce single-use with `GET → check → SET` (TOCTOU). Concurrent
     requests with the same nonce could both pass the replay check.
     Added atomic `setIfNotExists` (`SET NX EX`) on the RedisAdapter
     and used it for the nonce claim.
  10. **§2.4 revalidate** — `/callback` always called `issueNewKey`
     even for `kind='revalidate'` sessions where SPEC §2.4 step 6
     mandates "Token discarded (NOT stored)". Now branches: revalidate
     refreshes `last_revalidated_at` only; `encrypted_payload`
     becomes nullable on the `completed` response variant.
  11. **§2.2.4 webhook redelivery** — `/webhooks` returned 'duplicate'
     for any ON CONFLICT hit, including rows where the previous
     attempt had FAILED. Combined with the iter 56 webhook-replay
     fix, a transient DB blip during cascade left the revoke
     PERMANENTLY missed: replay would trigger redelivery forever
     and every retry was a silent no-op. Now branches on
     `existing.status` — 'failed' re-runs actions; idempotent
     applyAction makes that safe.
  12. **§2.2.2 concurrent registration race** — two same-identity
     /callback requests would race the SELECT-FOR-UPDATE → INSERT
     path; second would hit `agent_identities_unique_active` 23505
     → opaque 500. Fixed via Postgres advisory lock keyed on
     hashtextextended(`identity:{provider}|{subject}|{audience}`).
  13. **§4.3 unhandled-rejection storm** — `tierBCommit`'s
     `Promise.race` against the timeout left the operation pending
     when the timeout won; late rejections (the slow commit
     ultimately erroring with XX098) became unhandled-rejection
     warnings. Under stuck-standby load, that storm became the
     misleading alert signal. Fix: `.catch(() => undefined)` on the
     operation BEFORE the race so late rejections are silently
     absorbed.
  14. **§5.1.1 idempotency reservation race** — phase-1 used
     SELECT FOR UPDATE → INSERT; the FOR UPDATE on a non-existent
     row holds no lock, so two concurrent same-key calls both
     proceeded to INSERT and the second hit PK 23505 → opaque 500.
     The very failure mode idempotency is meant to prevent. Fixed
     via INSERT … ON CONFLICT (key) DO NOTHING RETURNING (xmax = 0)
     — atomic, race-free.
  15. **§2.7.3 rotation-grace expirer missing** — SPEC mandates a
     60s job that flips `rotation_state='rotating'` →`'rotated'`
     once grace expires. The job didn't exist. Added
     `expireRotationGrace` (hygiene only — validateKey already
     rejects grace-expired rows with 401, so unflipped rows are
     safe).
  16. **subscribePattern cross-talk** —
     `IoredisAdapter.subscribePattern` installed a fresh
     `pmessage` listener per call, but ioredis fires `pmessage`
     for ANY active pattern subscription. Two subscribePattern()
     calls (e.g., `:invalidate:key:*` and `:invalidate:account:*`)
     each had their callback fire for EVERY message, regardless
     of which pattern matched. SaaS apps subscribing both
     namespaces would mis-route invalidations + log labels.
     Fix filters by ioredis's first arg (matched pattern) inside
     the listener. Integration test against real Redis confirms
     each callback receives only its own pattern's messages.
  17. **§3.8 audit chain TZ misalignment** — the
     `compute_audit_row_hash` trigger used
     `date_trunc('day', NEW.ts)` for the per-day chain seed.
     `date_trunc/2` respects the SESSION timezone, not UTC. The
     daily partition manager (UTC-bound) and the hourly verifier
     (UTC-scoped) disagreed with the trigger if a SaaS team's
     Postgres session was non-UTC: rows on either side of UTC
     midnight would chain together (because they fell in the
     same local day), and the verifier seeding with ZERO_HASH
     for the new UTC day would surface a false break at the
     start of every UTC day. Migration `0005_audit_chain_utc.sql`
     adds explicit `'UTC'` arg to `date_trunc` (PG14+ form).
     Regression integration test in `audit-chain.int.test.ts`
     (with `SET TIME ZONE 'America/Los_Angeles'`) fails before
     the migration and passes after.
  18. **§6.4.2 outbox starvation** — `flushAuditOutbox`'s
     working SELECT was `WHERE flushed_at IS NULL ORDER BY
     created_at ASC LIMIT batch_size`. Stuck rows (attempts ≥
     max_attempts) passed the filter and consumed LIMIT slots.
     Once `batch_size` rows piled up as stuck, the flusher's
     entire pass would hit the stuck guard and continue, never
     reaching newer outbox rows. RT-39 silent: a sustained S3
     outage past the per-row retry budget would, after a
     transient blip later, leave the new rows unflushed
     forever. Fix splits the working SELECT (`attempts <
     max_attempts`) from a separate stuck-row SELECT used only
     for alerting; new outbox writes drain even when the queue
     is dominated by stuck rows. Three-test unit harness
     (one fresh + N stuck) demonstrates the bug pre-fix and
     the fix post-fix.
  19. **§10.1 registration-status add_key rejection** — SPEC
     §10.1 declares the request body as
     `{ "poll_token": "pak_..." | "pad_..." }` — both register
     and add_key tokens are valid at /registration-status. Our
     handler used `Record<endpoint, SessionKind>` so endpoint=
     'registration' only accepted `pak_`; a legitimate
     pad_-token poll fell through to the RT-21 mismatch branch
     and got 410 invalid_kind. Effect: the entire add_key flow
     (§2.5) was unreachable through /registration-status, even
     though /begin-registration with intent='add_key' issued the
     pad_ token correctly. Fix: kinds are now an array per
     endpoint — registration→[register, add_key], recover→
     [recover]. Unit regression confirms pad_ → completed.
  20. **RT-26 redis-down validation 500** — `validateKey`
     awaited `redis.getAuthoritativeEpoch()` and `redis.get(...)`
     with no try/catch. A complete Redis outage made every
     authenticated call 500 even though Postgres was healthy —
     direct violation of RT-26 ("Validation falls through to
     Postgres on epoch mismatch or Redis unavailability") and
     RT-3 ("Cache only; worst case 30s stale auth"). Fix wraps
     both Redis reads in try/catch; on failure we set
     `redis_available=false`, skip cache layers, and serve from
     Postgres directly. Local-cache writes still happen so a
     repeat in-process call during the outage can hit local
     cache (RT-3-bounded staleness). Two unit regressions
     simulate getAuthoritativeEpoch failure and redis.get
     failure; both fail before the patch and pass after.
  21. **§6.4 admin runbook missing in-tx audit** — `rbRevokeKey`
     and `rbSuspendAccount` are Tier B mutations (wrapped in
     `tierBIdempotent`) but didn't write an audit row inside
     the mutation transaction. The CLI dispatcher writes an
     "admin_<command>" intent row pre-handler, but per SPEC §6.4
     "every Tier B mutation MUST emit an audit row in the same
     transaction as the state change." Without the in-tx row,
     the hash chain has no record atomically linked to the
     commit (RT-39 vector: an attacker who can break the cli.ts
     pre-handler audit but not the in-tx one — or vice versa —
     can suppress evidence). Fix adds
     `writeAuditRowOnClient(client, ...)` after the
     `agent_revocation_log` INSERT in both runbooks. Two-row
     forensic trail per admin op: intent (cli.ts) + commit
     (in-tx). Integration test asserts both rows present.
  22. **§2.2.5 webhook-replay false-positive cap_hit** —
     `runWebhookReplay`'s post-loop check
     `if (pageCount >= max_pages) capHit = true` would fire
     spuriously whenever the loop broke via partial page,
     watermark, cutoff, or empty-page on iteration N where
     N == max_pages. Operators paged about a backlog that
     didn't exist; `last_run_status='cap_hit'` analytics
     over-counted. Fix: track `stoppedEarly` on every break
     path; cap_hit is `!stoppedEarly` — only true when the
     WHILE condition itself failed (real budget exhaustion).
     Three integration regressions: pre-watermark-only-50
     (cap_hit false), partial-on-last-iter (cap_hit false —
     pre-fix this was true), and a real cap-hit case
     (cap_hit true with onAlert). Also dropped the unused
     `hitWatermark` flag.
  23. **§5.1.2 reconciler skips pending → failed transition** —
     `reconcileUnknownIdempotency` flipped `unknown → failed` on
     not_found but left `pending` rows alone (the in-code comment
     said "use cap to do so"). Per SPEC §5.1.2, BOTH stale pending
     and unknown rows whose resource is not_found should promote
     to failed so retries see a cached `commit_lost` outcome
     instead of getting blocked at 425 idempotency_in_flight for
     the entire 25-min cap-out window. Fix: extend the WHERE
     clause to `state IN ('pending', 'unknown')`. The 0004 trigger
     allows pending → failed. Unit regression seeds a stale
     pending row + not_found resource state and asserts it
     transitions to failed; pre-fix the row stayed pending.
  24. **§7.2 logger meta keys can override canonical fields** —
     `createLogger().log` built records as
     `{ level, msg, ts, ...scrubbed }` so meta keys with the
     SPEC §7.2 reserved names (`ts`, `level`, `msg`) silently
     rewrote those fields. Effect: a SaaS logging an event whose
     scrubbed meta happened to include `level: 'debug'` would
     emit the record at the wrong severity, breaking log
     analytics and alerting. Fix flips the spread order so meta
     comes first, canonical fields last; a unit regression seeds
     a meta with `level/ts/msg` overrides and asserts the
     canonical fields win.
  25. **§8.1 JIT RBAC immortal grant via NaN ttl** —
     `JitRbac.grant({ ttl_seconds: NaN })` produced
     `expires_at = granted_at + NaN = NaN`. Subsequent
     `expires_at <= now()` checks compare against NaN and always
     return false — the grant lives forever, bypassing the 4h
     SPEC §8.1 cap. Also caught: `ttl_seconds = 0` and negative
     values create immediately-dead grants (UX footgun) and
     `Infinity` is safely capped but inconsistent. Fix rejects
     non-finite or non-positive `ttl_seconds` with 400
     invalid_request. Defense-in-depth — current call sites
     don't pass user input here, but a future one might.
  26. **§8.1 / RT-10 co-signer envelope substitution** —
     `verifyCoSignature` HMAC-signed `envelope.canonical` from the
     caller without checking it matched the envelope's part
     fields (op, target, timestamp, nonce, initiator,
     payload_sha256). Attack: take a co-signer's signature for a
     benign op (e.g. flush-cache *) and reuse it on an envelope
     whose canonical matches the benign op but whose `op` /
     `target` parts have been rewritten to a destructive op
     (close-account acc-victim). cli.ts's
     `envelope.op === input.command` guard sees the rewritten op
     vs the dispatcher's input — both attacker-chosen — so it
     dispatches the destructive command with a signature the
     co-signer never issued for it. Fix: reconstruct canonical
     from the part fields, reject on mismatch
     (`co_signer_canonical_mismatch`), and HMAC over the
     reconstructed bytes. Unit regression demonstrates the
     attack pre-fix and validates the defense.
  27. **§3.16 PostgresAdapter role SQL injection (defense in
     depth)** — `acquire()` interpolates `${this.role}` into
     `SET ROLE ${role}` on every checkout. The TypeScript
     `AppRole` union is the primary gate; a SaaS bypassing it
     via `as any` could SQL-inject (e.g. role =
     `agent_auth_app; DROP TABLE agent_accounts; --`). Fix adds
     a runtime whitelist check at constructor time. Unit
     regression covers all four allowed roles + a malicious
     value (rejection assertion).
  28. **§3.15 agent_jobs missing worker** — the
     `sync_account_tier_to_keys` trigger enqueued
     `cache_invalidate_keys` rows into `agent_jobs` but no code
     consumed them; rows accumulated and tier-change cache
     invalidation relied entirely on TTL. Implemented
     `processAgentJobs` (`src/jobs/process-agent-jobs.ts`):
     SELECT FOR UPDATE SKIP LOCKED claim, dispatch by `kind`,
     mark completed/failed/dead based on attempt count, alert
     on dead-letter and unknown kinds. Built-in handler for
     `cache_invalidate_keys`; SaaSes can register custom kinds
     via `extra_handlers`. 6 unit tests + 2 integration tests
     (against real Postgres) cover happy path, retry,
     dead-letter, unknown kind, and SKIP LOCKED concurrency.
