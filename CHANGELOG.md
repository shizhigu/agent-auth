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
