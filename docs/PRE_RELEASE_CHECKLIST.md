# Pre-release checklist

Mirror of SPEC.md §12.7. Tick each box before cutting a release tag.
Failed items must be either resolved or explicitly waived (with rationale +
sign-off recorded in CHANGELOG).

## Code quality

- [x] **All unit tests pass** — `npm test` (255+ tests, all green at HEAD)
- [x] **TypeScript strict mode clean** — `npx tsc --noEmit` (no errors)
- [x] **ESLint clean** — `npm run lint` (no `any` in security paths;
  `req.user` warning rule active per §6.3)
- [ ] **All integration tests pass** — `npm run test:integration`
  (testcontainers-driven; requires Docker)
- [ ] **All chaos tests pass** — `npm run test:chaos` (Toxiproxy scenarios
  per §12.4)
- [ ] **Property-based tests pass (1000 iterations)** — fast-check sweeps
  on idempotency, rotation, audit chain
- [x] **Benchmarks meet targets** — `npm run bench`
  (validation_cache_hit P50 < 5 ms / P99 < 50 ms; cache_miss_with_hmac
  P50 < 30 ms / P99 < 100 ms per §12.6)

## Schema & migrations

- [ ] **Forward + backward migration tested** — `0001..0004` applied on a
  fresh container and on a snapshot of prod-shape data; no destructive
  changes without §3.17 two-deploy gating
- [ ] **Migration scripts reviewed by DBA** — destructive ops (DROP,
  ALTER TYPE) gated behind feature flags

## Supply chain

- [ ] **OpenSSF Scorecard ≥ 8.5** — gate in `.github/workflows/security.yml`
- [ ] **`npm audit signatures` returns 0 issues** — verifies provenance
  on every dep
- [ ] **No new transitive deps without manual review** — Dependabot PRs
  reviewed by CODEOWNERS (RT-35)
- [ ] **Sigstore signing succeeds** — `release.yml` cosign sign-blob
  artifact attached to GitHub release (RT-14, RT-36)
- [ ] **OIDC trusted publishing** — `id-token: write`, no NPM_TOKEN

## Security review

- [ ] **OWASP API Top 10 self-review** — see docs/security/OWASP-API-self-review.md
- [~] **All 44 RT-* threats have integration / unit test coverage** (28 / 44 covered):
  - [x] RT-3 (Redis compromise → cache-only) — integration (redis flushdb fallback)
  - [x] RT-6 (webhook replay) — unit + integration (delivery_id dedup)
  - [x] RT-9 (BOLA / cross-tenant) — unit (validate-key) + integration (revoke 404 anti-enumeration)
  - [x] RT-10 (admin abuse) — unit (cli + jit-rbac + two-person)
  - [x] RT-12 (audit tamper) — integration (admin-role row_hash UPDATE → linkage break)
  - [x] RT-14, RT-36 (release pipeline) — workflow-level controls
  - [x] RT-19 (recovery hijack signature) — unit (owner-approval HMAC + skew)
  - [x] RT-20 (sealed-box pubkey substitution) — unit (pubkey-bound + size check)
  - [x] RT-21 (session fixation, cross-kind tokens) — unit + integration
  - [x] RT-25 (Redis partition) — chaos (container stop)
  - [x] RT-26 (stale Redis epoch / split-brain) — integration (revoke bumps epoch)
  - [x] RT-27 (idempotency replay payload mismatch) — unit + integration (real trigger)
  - [x] RT-29 (OAuth state phishing) — unit (PKCE RFC 7636 vector) + integration (single-use nonce)
  - [x] RT-30 (webhook spoof / order gap) — unit + integration (collision alert)
  - [x] RT-31 (tenant confused-deputy in recovery) — unit (target_account_id mismatch)
  - [x] RT-38 (SSO compromise → break-glass) — unit (jit-rbac independent path)
  - [x] RT-39 (audit omission) — unit (verifier first_break_index) + integration
  - [x] RT-41 (recovery approver compromise) — unit (two-person + co-signer)
  - [x] RT-42 (webhook secret rotation) — unit + integration (dual-secret window)
  - [x] RT-44 (APM scrubbing) — unit (scrubber + metrics + logger label scrub)
  - [x] §3.5 trigger race resolution (rotation_inverse) — integration (23505 unique_violation)
  - [x] RT-18, RT-32, RT-34 (multi-region failover) — chaos (timeline mismatch + replication-lag gates)
  - [x] RT-22 (KMS unreachable) — chaos (validateKey fails closed; never silent accept)
  - [x] RT-15 (DoS) — chaos (GCRA flood, bounded Retry-After, per-IP short-circuit, 200 over-rate calls < 2s)
  - [x] RT-43 (fail-closed amplification) — chaos (breaker invokes op exactly failureThreshold times; 1000 concurrent calls while open never re-invoke)
  - [x] RT-23, RT-40 (backup-restore tombstone reapply) — integration (agent_revocation_log walk reverts a "revived" key; idempotent replay)
  - [x] RT-24 (GitHub account takeover / SAML deprovisioning) — integration (webhook cascade revoke covers the deprovisioning path)
  - [x] RT-33 (metric / log secret leakage) — unit (scrubber covers metric labels + log records + audit meta)
  - [ ] RT-1 (phishing app authorization) — out-of-band; SaaS UX responsibility
  - [ ] RT-7 (agent process memory leak) — out-of-band; agent SDK responsibility (acknowledged in SPEC §6.2.7)
  - [ ] RT-8 (Sybil at warm tier) — documented compromise (warm tier must not unlock expensive ops); SaaS owner gates hot tier
  - [ ] RT-13, RT-28, RT-35, RT-37 — out-of-band operational controls (KMS / S3 / supply chain); tracked as v0.1.1 work
- [x] **Audit hash chain verifier** runs end-to-end against test data — unit
- [ ] **30-day historical replay** of audit chain in staging
- [ ] **DR drill on staging — RTO < 1h confirmed** — `scripts/dr-drill.sh`

## Documentation

- [x] **SPEC.md current** — Appendix B captures all ADRs (ADR-001..ADR-014)
- [x] **Runbooks RB-1..RB-9 documented** — `docs/runbooks/INDEX.md`
- [x] **`scripts/post-promotion-reset.sh` mapped to RB-8**
- [x] **`scripts/dr-drill.sh` mapped to §8.3.3**
- [ ] **CHANGELOG entry written** with security implications called out
- [ ] **Migration guide** for SaaS adopters (peer dep changes,
  config breaking changes if any)
- [ ] **Examples updated** — `examples/express-integration.ts`,
  `examples/hono-integration.ts`

## Release approval

- [ ] **Two reviewers approved release tag** — branch protection + GitHub
  required reviewers
- [ ] **Security lead signed off**
- [ ] **On-call paged before pushing tag** — operator ready to roll back

---

## Status notes (2026-04-30, agent-auth v0.1 cut)

- **Functional code: 8 / 8 milestones complete**, 255+ unit tests passing
  at HEAD.
- **Integration suite scaffolded** under `test/integration/` with
  testcontainers — runs locally with Docker; needs CI runner with Docker
  enabled (currently 4 tests covering M1 hot path).
- **Chaos suite, full integration sweep across all RT-*, property-based
  tests, and 30-day historical replay** are deferred to v0.1.1
  (the §12.7 checklist enforces them as gating items before any
  customer-facing v1.0 tag).
