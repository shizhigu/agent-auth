# Pre-release checklist

Mirror of SPEC.md §12.7. Tick each box before cutting a release tag.
Failed items must be either resolved or explicitly waived (with rationale +
sign-off recorded in CHANGELOG).

Legend:
- `[x]` — done in this lib (code + tests / config in place)
- `[ ]` — pending (this lib's responsibility; must close before tag)
- `[~]` — partial (called out in body)
- `[op]` — operational / SaaS-side; cannot be fully closed at the lib
  layer (e.g., KMS hygiene, branch-protection enforcement, on-call)
- `[reserved]` — placeholder in the upstream SPEC

## Code quality

- [x] **All unit tests pass** — `npm test` (355 tests across 49
  suites, ~600 ms wall, all green at HEAD)
- [x] **TypeScript strict mode clean** — `npx tsc --noEmit` (no errors)
- [x] **ESLint clean** — `npm run lint` (no `any` in security paths;
  `req.user` warning rule active per §6.3)
- [x] **All integration tests pass** — `npm run test:integration`
  (testcontainers-driven; 73 tests, ~80 s wall)
- [x] **All chaos tests pass** — `npm run test:chaos` (14 tests across
  redis-partition / multi-region-failover / kms-unavailable /
  dos-rate-limit / fail-closed-amplification scenarios per §12.4)
- [x] **Property-based tests pass** — fast-check sweeps cover all
  four SPEC §12.5 example properties (run as part of `npm test`):
  GCRA invariants (total accepts in window ≤ burst, replenishment,
  weight accounting, tat monotonicity), idempotency state machine,
  canonicalRequestHash invariance, and audit hash chain linkage
  (intact + prev_hash/row_hash tampering + adjacent-row swap).
  Default 100–200 runs/property; tighten via fast-check's `numRuns`
  per-property when running an adversarial fuzz sweep before tag.
- [x] **Benchmarks meet targets** — `npm run bench`
  (validation_cache_hit P50 < 5 ms / P99 < 50 ms; cache_miss_with_hmac
  P50 < 30 ms / P99 < 100 ms per §12.6 — current: 2.5 µs / 4.3 µs hit,
  4.6 µs / 9.0 µs miss)

## Schema & migrations

- [x] **Forward + backward migration tested** — `0001..0006` applied on a
  fresh container, schema smoke-tested, rolled back via `*.down.sql` in
  reverse order, verified empty, re-applied — round-trip is automated in
  `test/integration/migrations.int.test.ts`. Idempotent re-apply on an
  already-migrated DB also covered. Production-snapshot replay against
  prod-shape data is a separate operational gate; lib-side coverage is
  the round-trip + idempotency tests.
- [op] **Migration scripts reviewed by DBA** — destructive ops (DROP,
  ALTER TYPE) gated behind feature flags. Operational: each
  deploying SaaS team's own DBA review process.

## Supply chain

- [x] **OpenSSF Scorecard configured** —
  `.github/workflows/security.yml` runs `ossf/scorecard-action@v2.4.0`
  on push + PR + weekly schedule, results uploaded to GitHub
  code-scanning. The ≥8.5 threshold is enforced via branch protection
  on `main` (operational gate at the deploying repo).
- [x] **npm publish provenance + signatures** — `release.yml` uses
  `npm publish --provenance` with `id-token: write` (OIDC trusted
  publishing); no NPM_TOKEN. `npm audit signatures` runs as part of
  `npm ci` provenance verification.
- [x] **Dependabot reviewer guard for new deps** —
  `.github/dependabot.yml` configures weekly npm + github-actions
  updates with explicit reviewer (RT-35). CODEOWNERS routes review to
  the owner.
- [x] **Sigstore signing of release blob** — `release.yml` runs
  `cosign sign-blob --yes --bundle release.cosign.bundle dist/index.js`
  + `anchore/sbom-action` SPDX SBOM (RT-14, RT-36).
- [x] **OIDC trusted publishing** — `release.yml` job sets
  `id-token: write` and uses `--provenance`; no NPM_TOKEN secret.

## Security review

- [x] **OWASP API Top 10 self-review** — `docs/security/OWASP-API-self-review.md`
  walks all 10 OWASP API 2023 risks against the lib's surface,
  enumerates the controls (with [x] markers) and explicitly
  delineates SaaS-side responsibilities
- [x] **All 44 RT-* threats accounted for** — 32 covered with
  unit/integration/chaos tests, 11 explicitly out-of-band
  (operational or SaaS-side), 1 reserved. None left without a
  documented disposition.
  - [x] RT-3 (Redis compromise → cache-only) — integration (redis flushdb fallback)
  - [x] RT-6 (webhook replay) — unit + integration (delivery_id dedup)
  - [x] RT-9 (BOLA / cross-tenant) — unit (validate-key) + integration (revoke 404 anti-enumeration)
  - [x] RT-10 (admin abuse) — unit (cli + jit-rbac + two-person)
  - [x] RT-12 (audit tamper) — integration (admin-role row_hash UPDATE → linkage break)
  - [x] RT-14, RT-36 (release pipeline) — workflow-level controls (release.yml + security.yml)
  - [x] RT-15 (DoS) — chaos (GCRA flood, bounded Retry-After, per-IP short-circuit, 200 over-rate calls < 2s)
  - [x] RT-18, RT-32, RT-34 (multi-region failover) — chaos (timeline mismatch + replication-lag gates)
  - [x] RT-19 (recovery hijack signature) — unit (owner-approval HMAC + skew)
  - [x] RT-20 (sealed-box pubkey substitution) — unit (pubkey-bound + size check)
  - [x] RT-21 (session fixation, cross-kind tokens) — unit + integration
  - [x] RT-22 (KMS unreachable) — chaos (validateKey fails closed; never silent accept)
  - [x] RT-23, RT-40 (backup-restore tombstone reapply) — integration (agent_revocation_log walk reverts a "revived" key; idempotent replay)
  - [x] RT-24 (GitHub account takeover / SAML deprovisioning) — integration (webhook cascade revoke covers the deprovisioning path)
  - [x] RT-25 (Redis partition) — chaos (container stop)
  - [x] RT-26 (stale Redis epoch / split-brain) — integration (revoke bumps epoch) + unit (Redis-down read fallback)
  - [x] RT-27 (idempotency replay payload mismatch) — unit + integration (real trigger)
  - [x] RT-28 (WORM write suppression) — unit + integration (Tier B writeAuditToWorm fails-closed with audit_unavailable when S3 put fails; outbox row still durable for retry)
  - [x] RT-29 (OAuth state phishing) — unit (PKCE RFC 7636 vector) + integration (single-use nonce)
  - [x] RT-30 (webhook spoof / order gap) — unit + integration (collision alert)
  - [x] RT-31 (tenant confused-deputy in recovery) — unit (target_account_id mismatch)
  - [x] RT-33 (metric / log secret leakage) — unit (scrubber covers metric labels + log records + audit meta)
  - [x] RT-38 (SSO compromise → break-glass) — unit (jit-rbac independent path)
  - [x] RT-39 (audit omission) — unit (verifier first_break_index) + integration
  - [x] RT-41 (recovery approver compromise) — unit (two-person + co-signer envelope substitution defense)
  - [x] RT-42 (webhook secret rotation) — unit + integration (dual-secret window)
  - [x] RT-43 (fail-closed amplification) — chaos (breaker invokes op exactly failureThreshold times; 1000 concurrent calls while open never re-invoke)
  - [x] RT-44 (APM scrubbing) — unit (scrubber + metrics + logger label scrub)
  - [x] §3.5 trigger race resolution (rotation_inverse) — integration (23505 unique_violation)
  - [op] RT-1 (phishing app authorization) — SaaS UX responsibility (consent screen, brand verification)
  - [op] RT-2 (transport pinning) — SaaS deployment responsibility (TLS pinning policy is service-side, not lib-side)
  - [op] RT-4 (backup compromise) — operational controls (encrypted backups, KMS-protected restore key)
  - [reserved] RT-5 — reserved in SPEC's threat list
  - [op] RT-7 (agent process memory leak) — agent SDK responsibility (acknowledged in SPEC §6.2.7)
  - [op] RT-8 (Sybil at warm tier) — documented compromise (warm tier must not unlock expensive ops); SaaS owner gates hot tier
  - [op] RT-11 (cross-tenant data leak in SaaS code) — SaaS-side: this lib only exposes `req.agent`; per-tenant query construction is the SaaS's responsibility
  - [op] RT-13 (backup-storage compromise) — operational control (KMS-bound backup encryption + access policy)
  - [op] RT-16 (cert pinning bypass) — operational (mTLS / network policy enforced at deployment)
  - [op] RT-17 (service-account credential theft) — operational (KMS / IAM hygiene + rotation)
  - [op] RT-35 (npm dependency typosquat) — operational (Dependabot reviewer guard + manual review of transitive deps; .github/dependabot.yml)
  - [op] RT-37 (KMS root key rotation) — operational (KMS lifecycle policy at deployment)
- [x] **Audit hash chain verifier** runs end-to-end against test data —
  unit + integration (audit-chain.int includes cross-day independence
  + RB-6 forensic target_day verification)
- [op] **30-day historical replay** of audit chain in staging — code
  side: `verifyChain` + `verifyChainStrict` + RB-6 forensic
  target_day verification covered by integration tests; the actual
  30-day replay against staging data is the deploying team's
  pre-tag operational gate.
- [op] **DR drill on staging — RTO < 1h confirmed** —
  `scripts/dr-drill.sh` is mapped to SPEC §8.3.3; the actual drill
  is operational (deploying team executes against staging).

## Documentation

- [x] **SPEC.md current** — Appendix B captures all ADRs (ADR-001..ADR-014)
- [x] **Runbooks RB-1..RB-9 documented** — `docs/runbooks/INDEX.md`
- [x] **`scripts/post-promotion-reset.sh` mapped to RB-8**
- [x] **`scripts/dr-drill.sh` mapped to §8.3.3**
- [x] **CHANGELOG entry written** with security implications called out
  — post-v0.1 sweep summary covers ~30 caught bugs + 4 new
  features (agent_jobs worker, reapExpiredRows, deferred
  recovery, migrations round-trip), with RT-numbered references
- [x] **Migration guide** for SaaS adopters — `docs/MIGRATION_GUIDE.md`
  walks the post-v0.1-sweep upgrade path: apply migrations 0005 +
  0006, optionally pass `kms` to `recoverAccountConfirm` deps,
  schedule `processAgentJobs` + `reapExpiredRows` jobs. Documents
  the new /callback deferral semantics, the session TTL extension,
  what's NOT changing, testing instructions, and a rollback plan.
- [x] **Examples updated** — `examples/express-integration.ts`,
  `examples/hono-integration.ts`, plus the new
  `examples/worker-cronjobs.ts` covering the SPEC §13.1.2
  background-worker cadence (reapers, hash-chain verifier,
  partition manager, rotation-grace expirer, webhook replay,
  idempotency reconciler, processAgentJobs worker, expired-rows
  reaper, Redis SET reconciliation). All three pass strict-mode
  typecheck.

## Release approval

- [op] **Two reviewers approved release tag** — branch protection +
  GitHub required reviewers (operational; configured per-repo
  on the deploying SaaS's fork or the maintainer's npm publishing
  org)
- [op] **Security lead signed off** — operational; deploying
  team's release sign-off process
- [op] **On-call paged before pushing tag** — operational; deploying
  team's incident readiness

---

## Status notes (2026-04-30, agent-auth v0.1 cut)

- **Functional code: 8 / 8 milestones complete**, 355 unit tests passing
  at HEAD across 49 suites (added: GCRA + audit-chain property
  tests, AwsKmsAdapter + AwsS3WormPutter mock-driven coverage, lease
  expiry recovery, expired-rows reaper, deferred recovery, etc).
- **Integration suite mature** under `test/integration/` with
  testcontainers — 73 tests, ~80 s wall, covering all M1-M8 routes +
  cross-region barrier + audit chain (cross-day independence + RB-6
  forensic mode) + audit partition manager + Tier B audit_unavailable
  fail-closed (RT-28) + RT-31 cross-tenant recovery + RT-42 webhook
  secret rotation. Runs locally with Docker; needs CI runner with
  Docker enabled.
- **Chaos suite is in tree and green** — 14 tests covering
  redis-partition (RT-25), multi-region-failover (RT-18/RT-32/RT-34),
  kms-unavailable (RT-22), dos-rate-limit (RT-15), fail-closed-
  amplification (RT-43).
- **Property-based tests, 30-day historical replay, and the v1.0 tag
  gate** remain v0.1.1 work; the §12.7 checklist still enforces them
  as gating items before any customer-facing tag.
