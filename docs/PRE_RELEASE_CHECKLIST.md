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
- [ ] **All 44 RT-* threats have integration / unit test coverage**
  - [x] RT-3, RT-25, RT-26 (cache fallback, epoch invalidation) — integration
  - [x] RT-6, RT-30, RT-42 (webhook replay, collision, secret rotation) — unit
  - [x] RT-9 (cross-tenant) — unit (validate-key) + integration
  - [x] RT-12, RT-39 (audit tamper, omission) — unit (verifier) + DB-level trigger
  - [x] RT-14, RT-36 (release pipeline) — workflow-level controls
  - [x] RT-19, RT-31, RT-41 (recovery hijack, confused deputy) — unit
  - [x] RT-20 (sealed-box pubkey substitution) — unit
  - [x] RT-21 (session fixation, cross-kind tokens) — unit
  - [x] RT-27 (idempotency replay payload mismatch) — unit
  - [x] RT-29 (OAuth state phishing) — unit (PKCE) + integration (callback)
  - [x] RT-44 (APM scrubbing) — unit (scrubber + metrics + logger)
  - [ ] RT-15 (DoS), RT-43 (fail-closed amplification) — chaos suite
  - [ ] RT-18, RT-32, RT-34 (multi-region failover) — chaos suite
  - [x] RT-10, RT-38 (admin abuse, SSO compromise → break-glass) — unit
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
