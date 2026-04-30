# Changelog

All notable changes to `agent-auth` will be documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — v0.1 cut

Initial implementation of the agent-auth library, delivering all 8 milestones
from SPEC.md §11.2.

- **M1 Core data model + validation** — Postgres schema migrations 0001-0004
  (type domains, accounts, identities, api_keys, sessions, device_flows,
  audit_log partitioned + hash-chain trigger, idempotency state machine,
  revocation epoch + barrier singletons, recovery approvals); KMS adapter
  (AWS + in-memory test); HMAC + KMS pepper crypto with 7-day dual-window
  rotation; Postgres role-aware adapter; Redis adapter with Lua MAX
  (epoch_max) and GCRA scripts; in-process LRU cache with 30 s TTL;
  audit-hash canonicalization mirroring the §3.8 trigger; PKCE S256;
  validate-key middleware (local → Redis → Postgres) per §5.3.3;
  Express + Hono framework adapters with X-Request-Id + scrubbed error
  bodies per §10.3; AgentAuthConfig type and `resolveConfig()` defaults.

- **M2 GitHub App registration** — `GitHubAppProvider` with browser flow
  (authorize URL builder + code exchange + Attestation construction +
  App-JWT revalidate); `issueNewKey` shared helper (HMAC + base64url
  wire form); `/begin-registration`, `/registration-status`, `/callback`
  routes (full §2.2.2 case A/B/C/D pipeline + RT-29/RT-31 guards);
  sealed-box (libsodium `crypto_box_seal`) per §2.6 / ADR-004;
  registration-session reaper.

- **M3 Rotation + Revocation + Idempotency** — `tierBCommit` wrapper with
  XX098 detection; `tierBIdempotent` two-phase reservation + observer
  (`reconcileUnknownIdempotency`) per §5.1; `bumpEpochInTx` + Lua MAX
  push to Redis; `captureBarrierAfterCommit`; `invalidateKey` /
  `invalidateAccountKeys` cache pipeline; `/revoke` (Tier B + idempotent
  + audit_log + barrier); `/rotate-key` (planned grace + emergency,
  with optional sealed-box delivery for the new key).

- **M4 Webhooks + reconciliation** — `GitHubAppProvider.handleWebhook`
  with HMAC-verify-first + dual-secret rotation window (RT-42);
  `/webhooks/:provider` route with atomic dedup + cascade revoke +
  account suspension (no-other-primary-active); webhook replay polling
  job (`runWebhookReplay`) per §2.2.5.

- **M5 Rate limiting + observability** — GCRA Lua script + multi-dimensional
  `enforceRateLimits()` middleware per §5.2; circuit breaker for upstream
  IdPs per §5.4; observability scrubber (key-name + value-pattern +
  high-entropy heuristic + size caps per §6.6); Prometheus-format metrics
  registry; structured JSON logger that runs every record through the
  scrubber.

- **M6 Recovery + multi-region** — `/recover-account`, `/recover-account-status`,
  `/recover-account-confirm` routes with canonical owner-approval HMAC
  (RT-19) and Redis SET-NX nonce single-use; multi-region barrier read
  path (`makeBarrierCheck` with timeline-mismatch and replay-lag gates,
  fail-closed and route-to-primary policies); `scripts/post-promotion-reset.sh`
  for RB-8.

- **M7 Audit + compliance** — `writeAuditRow` + `pseudonymizeIp` against
  the §3.8 hash chain trigger; `writeAuditToWorm` with S3 Object Lock
  COMPLIANCE + outbox fallback; `flushAuditOutbox` retry job;
  `verifyAuditChain` linkage-only verifier per §6.4.1;
  `scripts/dr-drill.sh` quarterly drill harness.

- **M8 Admin CLI + supply chain** — JIT-RBAC grant + assertion;
  two-person rule with canonical co-signer envelope; `WebAuthnVerifier`
  interface; `runAdminCommand` dispatcher (JIT → WebAuthn → two-person →
  audit-then-dispatch); RB-1..RB-7 + RB-9 handlers (RB-8 already shipped
  as a script in M6); `reconcileAccountKeySets` for §5.3.6;
  `.github/workflows/{ci,release,security}.yml` with OIDC trusted
  publishing + Sigstore + Scorecard + TruffleHog; `.github/CODEOWNERS`;
  `.github/dependabot.yml`; `.npmrc` with provenance enabled.

- **Cross-cutting** — `docs/PRE_RELEASE_CHECKLIST.md` mirrors §12.7;
  testcontainers harness for integration tier; Toxiproxy-style + container-
  stop chaos suite; fast-check property tests on idempotency state
  machine + canonical request hash.

### Added since initial v0.1 cut

- **`GET /keys`** (§10.1) — admin:keys-scoped projection of caller's
  account keys; revoked rows excluded; cross-account guard.
- **`GET /healthz`** (§10.2) — barrier + Redis + circuit-breaker probe;
  200 healthy / 503 unhealthy with `reasons[]` aggregation.
- **`GET /.well-known/agent-auth`** (§10.1) — service discovery body
  composer; per-provider capability overrides; ValidationMode →
  `barrier_mode` string translation.
- **In-tx audit emission across all Tier B routes** (§6.4) —
  `writeAuditRowOnClient(client, ...)` in-tx variant; wired into
  /revoke, /rotate-key (planned + emergency), /webhooks cascade,
  /callback (all kinds), /recover-account-confirm. The in-DB hash
  chain now captures every Tier B mutation atomically.
- **Daily audit-log partition manager** (§3.8 / §13.1.2) — pre-creates
  `agent_audit_log_YYYY_MM_DD` partitions for the next N days; idempotent
  on rerun. Migration 0002 sets parent OWNER to `agent_auth_migrator`
  so the partition job can attach.
- **`docs/break_glass.md`** (§8.1 / RT-38) — operator procedure for
  the independent break-glass admin path (physical YubiKeys + sealed
  envelopes, two-person, 24h post-mortem).

### Fixed since initial v0.1 cut

- **Tier B WORM failure now fails-closed** (§6.4.2 / RT-28) —
  `writeAuditToWorm` was silently returning `outboxed` for Tier B
  events when the S3 put failed, which would let an attacker who
  suppresses S3 get a free pass to revoke/rotate without producing a
  durable WORM record. Now throws `ServiceUnavailableError(audit_unavailable)`
  for Tier B (outbox row still durable for retry); Tier A unchanged.
- **`/recover-account-confirm` concurrency** — the `SELECT FOR UPDATE`
  was running on `deps.postgres.queryOne` (fresh pooled connection per
  call), so the row lock was released the instant queryOne returned.
  The read-modify-write is now wrapped in a single `transaction()`,
  which holds the lock across the UPDATE and lets the audit row commit
  atomically with the decision.
- **`config.audit_worm` type alignment** — was a stub
  `{putObject({Key, Body})}` that never matched the real `WormPutter`
  interface. Now typed as `WormPutter`; SaaS apps can wire
  `AwsS3WormPutter` directly via config.

### Added in the post-v0.1 correctness sweep (continued)

- **`processAgentJobs` worker** (§3.15) — generic claim+dispatch
  worker for the `agent_jobs` queue. SELECT FOR UPDATE SKIP LOCKED;
  built-in `cache_invalidate_keys` handler; SaaS-extensible via
  `extra_handlers`. Dead-letter alerting after `max_attempts`;
  unknown kinds marked completed with alert. Lease-expiry
  reclaims rows whose worker died mid-run (default 5 min lease).
- **`reapExpiredRows`** (§3.14, §5.1.1, §6.4.2, §3.15) — drains
  `agent_recovery_approvals`, `agent_idempotency` (terminal states
  only), `agent_audit_outbox` (post-flush), and `agent_jobs`
  (terminal states) past their respective retention grace.
- **§2.9 owner-approval-gated recovery** — `/callback` now defers
  key issuance when the approval row is `pending`, persisting the
  OAuth-verified identity_id on the session via the new
  `awaiting_identity_id` column (migration 0006).
  `/recover-account-confirm` finalizes on `approved` (issues key,
  seals, transitions session to `ready`) and fails on `denied`.
  `emitOwnerApprovalRequest` also extends session `expires_at` to
  match the approval window so a slow owner doesn't lose the
  session to the reaper.
- **Migration 0005** — `compute_audit_row_hash` trigger uses
  `date_trunc('day', NEW.ts, 'UTC')` instead of session-tz form;
  prevents false hash-chain breaks on non-UTC Postgres sessions.
- **Migrations round-trip integration test** — automates SPEC §3.17
  forward+backward+forward verification.
- **Property tests** (§12.5 partial) — fast-check sweeps over
  idempotency state machine + `canonicalRequestHash`.

### Fixed in the post-v0.1 correctness sweep (continued)

Selected highlights — full per-iteration log in
`IMPLEMENTATION_STATUS.md` sweep entries 1..31. Net: ~30 bugs
caught reading the SPEC alongside code, none of which were
caught by the existing test suite.

- **RT-10 two-person-rule envelope substitution** (§8.1) —
  attacker could reuse a co-signer's signature for a benign op
  on an envelope rewritten to a destructive op.
  `verifyCoSignature` now reconstructs canonical from envelope
  parts; mismatches fail fast.
- **RT-26 redis-down 500** — `validateKey` propagated Redis
  exceptions through to a 5xx; SPEC says fall through to
  Postgres. Now skips cache layer when Redis throws.
- **§3.8 audit chain TZ misalignment** — see migration 0005.
- **§5.1.1 idempotency reservation race** — replaced
  `SELECT FOR UPDATE → INSERT` with `INSERT ... ON CONFLICT DO
  NOTHING RETURNING (xmax=0)` (FOR UPDATE on missing rows holds
  no lock).
- **§5.1.2 reconciler skipped pending → failed** — only flipped
  unknown rows; SPEC says both pending and unknown.
- **§6.4.2 outbox starvation** — stuck rows filled the working
  SELECT's LIMIT slots, blocking fresh writes.
- **§2.2.5 webhook-replay false-positive cap_hit** — partial-page
  break with pageCount==max_pages incorrectly fired the alert.
- **§2.2.4 webhook redelivery of failed deliveries** — duplicate
  delivery returned 'duplicate' even when the prior attempt
  failed; replay would silently no-op forever.
- **§7.2 logger meta keys could override `level`/`msg`/`ts`** —
  spread order was wrong.
- **§8.1 JIT RBAC NaN-ttl immortal grant** — NaN expires_at
  evades the `<= now()` check.
- **§3.16 PostgresAdapter role SQL injection (defense in depth)**
  — runtime whitelist on the constructor.
- **§4.3 tierBCommit unhandled-rejection storm** — late
  `Promise.race` losers had no handler.
- **§2.7.3 rotation-grace expirer added** — 60s job flips
  `rotating → rotated` once grace expires.

### Decisions

- **ADR-014** — `tierBCommit` is the sole converter of `TierBTimeoutError`
  / pg `XX098` to `ServiceUnavailableError`. `tierBIdempotent` catches
  the converted error, marks `state='unknown'`, re-throws as
  `idempotency_unknown_outcome`. Resolves the §4.3 ↔ §5.1.1 SPEC tension
  about which catch clause owns the timeout.

### Known v0.1 deferrals (tracked in PRE_RELEASE_CHECKLIST.md)

- Device flow is deferred (browser flow is v0.1 default per §2.2.1).
- 30-day historical audit replay, DR drill on staging, OpenSSF Scorecard
  ≥ 8.5 gate, OIDC trusted publishing — all require staged
  deployment, not testable in-repo.
- Out-of-band RT items (RT-1 phishing UX, RT-7 agent process leakage,
  RT-8 warm-tier Sybil, RT-13 / RT-28 / RT-35 / RT-37 operational
  controls) — explicitly enumerated as acknowledged compromises or SaaS
  responsibilities per SPEC §6.2.7.

### Security notes for adopters

- Authentication state lives in `req.agent` only — never `req.user`. The
  ESLint rule shipped in `.eslintrc.cjs` warns on `req.user` usage in
  routes that mount the agent middleware. Type augmentation lives in
  README.md and `examples/express-integration.ts`.
- All Tier B mutations require an `Idempotency-Key` header. Replay with
  the same key + payload returns the cached response. Replay with the
  same key + different payload surfaces 409
  `idempotency_key_payload_mismatch` (RT-27).
- Web hook verify-first: the lib will refuse to dedup-INSERT a webhook
  body whose HMAC does not match. Attackers cannot poison the dedup
  table with a forged `X-GitHub-Delivery`.
