# Security policy

## Reporting a vulnerability

**Do not file public issues for security reports.**

Email `security@szgu.dev` (or, until that mailbox exists, open a GitHub
*draft security advisory* on the repo). Include:

- A short description of the issue.
- Steps to reproduce, with a minimal code sample if possible.
- The version (`git rev-parse HEAD` output) you tested against.
- Whether you believe the issue is exploitable in production deployments
  vs. only in a contrived test environment.

We aim to acknowledge reports within **2 business days**.

## Disclosure timeline

| Stage | Target |
|---|---|
| Acknowledge report | within 2 business days |
| Triage + assign severity | within 5 business days |
| Mitigation in main + tagged release | within 30 days for high-severity |
| Public disclosure | 90 days after report OR coordinated with reporter |

We follow a **90-day disclosure window** (CERT/CC tradition). If a fix
ships earlier we will credit the reporter in the release notes (with
their consent).

## Scope

In-scope:

- Anything in `src/` that affects authentication correctness, key
  confidentiality, audit integrity, or tenant isolation.
- The Postgres schema migrations under `schema/migrations/`.
- The build / release pipeline under `.github/workflows/`.

Out-of-scope:

- Issues that require root on the SaaS host running the lib (RT-7 per
  SPEC §6.2.7 — outside lib boundary).
- Issues that require the SaaS to misconfigure the lib in ways that
  contradict `docs/PRE_RELEASE_CHECKLIST.md`.
- Vulnerabilities in third-party services the lib integrates with
  (GitHub OAuth, AWS KMS, AWS S3) — please report those to the
  responsible vendors.

## Threat model

The lib's threat model is documented in **SPEC.md Part VI**. Each of the
44 RT-* threats is mapped to a mitigation, and the test suite exercises
33 of them automatically (see `docs/PRE_RELEASE_CHECKLIST.md`). The
remaining 11 are SaaS-side or operational controls outside the test
harness.

## Supported versions

The lib follows semantic versioning. Security fixes are backported to
the most recent **minor** in the latest **major** stream. Older majors
stop receiving fixes 12 months after the next major ships.

| Version | Status |
|---|---|
| 0.1.x | active development |
| (future) 0.2+ | supported |
| pre-0.1 | unsupported (drop) |
