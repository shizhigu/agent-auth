<!-- Thanks for contributing to Vouch!

Vouch is roadmap-driven (see README → Roadmap). Linking an issue helps us
align on the change shape before review:

- Bug-fix PRs: linked issue → fast-tracked.
- Feature PRs: please open an issue first to align on the design.
- SPEC.md / src/crypto/ / src/middleware/validate-key.ts / src/distributed/
  changes: discuss in an issue first; ADR required for spec touches.

Full guidelines: https://github.com/shizhigu/agent-auth#contributing
-->

## Linked issue

Closes #<!-- issue number — strongly preferred for non-trivial changes -->

## Summary

<!-- 1-3 bullets describing the change. -->

## What kind of change

- [ ] Bug fix (linked issue exists)
- [ ] Feature aligned with the v0.2 / v0.3 roadmap
- [ ] Documentation
- [ ] Test-only change
- [ ] Other

## Test plan

- [ ] `npm test` passes
- [ ] `npm run typecheck` passes
- [ ] `npm run lint` passes
- [ ] `npm run test:integration` passes (if your change touches I/O paths)
- [ ] New / changed behavior is covered by a test

## Spec impact

- [ ] No `SPEC.md` change
- [ ] `SPEC.md` change with an ADR added to Appendix B (ADR-001..ADR-014 are the format)

## Security considerations

<!-- If your change touches auth logic, KMS, audit chain, or anything in
src/crypto/, src/middleware/validate-key.ts, src/identity/, or
src/distributed/ — please call out the threat model implication here. -->
