# Contributing to agent-auth

Thanks for helping! This file describes how to set up the dev environment,
run the test tiers, and submit changes.

## Dev setup

```bash
git clone https://github.com/shizhigu/agent-auth.git
cd agent-auth
npm ci

# Sanity check (1s)
npm run typecheck
npm test
```

For integration / chaos / bench you also need Docker:

```bash
# Boots Postgres + Redis containers via testcontainers
npm run test:integration   # ~30s
npm run test:chaos         # ~10s
npm run bench              # ~5s
```

## Test tiers

| Tier | Scope | Wall | Network |
|---|---|---|---|
| **unit** | pure-Node tests, in-memory adapters | <1s | none |
| **integration** | real Postgres + Redis + KMS via testcontainers | ~30s | Docker |
| **chaos** | injected faults (container stop, mock failures) | ~10s | Docker |
| **bench** | hot-path microbench | ~5s | none |

Property-based tests (`*.property.test.ts`) live under `test/unit/` and
run with the unit tier. Use `fast-check` for any new property tests.

## Commit conventions

- Subject line ≤ 72 chars, imperative mood.
- Reference SPEC sections (e.g. `§5.3.3`) when implementing a behavior
  documented there.
- Reference RT-* threat numbers when mitigating them.
- Reference ADR-* numbers when introducing or deviating from one.
- Never amend published commits; cut a new commit instead.

Commit message body should explain *why* — the *what* is in the diff.

## Branch protection

`main` is protected:

- All CI workflows must pass (`ci.yml`, `security.yml`).
- One reviewer approval required.
- Tags (`v*.*.*`) require an additional environment-gated approval before
  the release workflow runs (Sigstore signing + npm provenance).

## ADRs

Architectural decisions live in `SPEC.md` Appendix B. Any change that
deviates from SPEC.md (or any new cross-cutting decision) requires a new
ADR appended to that appendix. The format is:

```
## ADR-NNN: One-line decision

**Decision**: ...
**Drivers**: ...
**Consequence**: ...
```

If the deviation is local to a migration file or test helper, log it in
`IMPLEMENTATION_STATUS.md` under "Notes / deviations / blockers" with a
date and reasoning.

## Reporting security issues

See [SECURITY.md](./SECURITY.md). Please do not open public issues for
security reports.

## Code review priorities

When reviewing a PR, check in this order:

1. **Confused-deputy** — does any change touch route handlers that read
   `req.agent`? Confirm `req.user` is never read in the same path.
2. **Tier B mutations** — every Tier B operation (revoke, emergency
   rotate, suspend, close) must go through `tierBIdempotent`. PRs that
   add a new mutation route MUST classify the operation in §4.2.1 / §4.2.2.
3. **Threat model** — every new public route should be mapped to the
   relevant RT-* mitigations in `SPEC.md` Part VI.
4. **Test pyramid** — unit-level for logic, integration for state-machine
   invariants, chaos for failure modes. New routes need at least unit
   tests; new SQL triggers need integration tests.
5. **Crypto** — never roll your own. Use the existing primitives:
   `hmac-pepper.ts`, `sealed-box.ts`, `pkce.ts`, `audit-hash.ts`.
6. **Scrubber** — any new logging surface must use `defaultScrubber` /
   the structured logger (RT-44).
