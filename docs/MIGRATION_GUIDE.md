# Vouch (`@vouch/server`) migration guide

This guide walks SaaS adopters through what changed between
versions, what's required to upgrade, and what's optional but
recommended.

> **TL;DR for the v0.1.x correctness sweep (post-v0.1 cut):** apply
> migrations 0005 + 0006, optionally pass `kms` to
> `recoverAccountConfirm` deps, and schedule the new
> `processAgentJobs` + `reapExpiredRows` jobs in your worker pod.
> No breaking config changes.

---

## Upgrading inside v0.1.x

### 1. Run the new schema migrations

```sh
psql "$DATABASE_URL" \
  -f schema/migrations/0005_audit_chain_utc.sql \
  -f schema/migrations/0006_recover_pending_approval.sql
```

- **0005 (audit chain UTC)** — replaces `compute_audit_row_hash`'s
  per-day chain seed query with the explicit `'UTC'` form of
  `date_trunc`. Without it, deployments running Postgres with a
  non-UTC session timezone would chain rows across UTC-day
  boundaries and the §6.4.1 verifier would surface false breaks at
  the start of every UTC day. **Idempotent** (`CREATE OR REPLACE
  FUNCTION`); existing audit rows are not rehashed. Operators who
  need byte-perfect chain parity across the migration boundary
  cross-reference WORM per RB-6.

- **0006 (recover_pending_approval)** — adds
  `awaiting_identity_id UUID NULL` to
  `agent_registration_sessions`. Required for the §2.9
  owner-approval gating to actually defer key issuance until the
  owner approves. **Additive** (column nullable, no default
  recompute).

Both migrations have matching `*.down.sql` files; the lib's
`test/integration/migrations.int.test.ts` automates the
forward+rollback round-trip.

### 2. Optionally pass `kms` to `recoverAccountConfirm` deps

If your SaaS configures `recover_account.owner_approval`, the
`/recover-account-confirm` route needs KMS to issue the deferred
key when the owner approves:

```ts
import { recoverAccountConfirm, AwsKmsAdapter, ... } from '@vouch/server';

await recoverAccountConfirm(input, {
  postgres: pg,
  redis,
  internal_secret: cfg.internal_secret,
  kms,  // ← was previously omittable; required only when
        //   owner_approval is configured AND a recovery
        //   session is in the deferred state.
});
```

If you don't configure `owner_approval`, the field stays optional —
the finalize path is gated on the session having a non-NULL
`awaiting_identity_id`, which only happens via the new /callback
deferral.

### 3. Schedule the new background jobs

Two new periodic jobs ship in v0.1.x:

- **`processAgentJobs`** (every ~5s) — drains the `agent_jobs`
  queue. The `sync_account_tier_to_keys` trigger has been emitting
  rows there since v0.1; this worker is what finally consumes them.
  SaaSes that issue tier changes will see immediate cache
  invalidation now (instead of relying on the 30s cache TTL).

- **`reapExpiredRows`** (every ~1min) — drains expired terminal
  rows from `agent_recovery_approvals`, `agent_idempotency`
  (terminal states only), `agent_audit_outbox` (post-flush), and
  `agent_jobs` (terminal states). Without this, those four tables
  grow unboundedly.

`examples/worker-cronjobs.ts` is a complete, runnable template
covering all SPEC §13.1.2 background workers.

### 4. /callback for kind='recover' may now return success without
emitting `encrypted_payload`

Before the sweep, `/callback` for kind='recover' always issued the
key + sealed it + transitioned the session to 'ready'.

Now, when the matching `agent_recovery_approvals` row has
decision='pending', /callback **defers** issuance:

  - Returns `{ status: 'success', is_first_key: false }`.
  - Session stays in `'exchanging'`; `result_ciphertext` stays NULL;
    `awaiting_identity_id` is set.
  - `/recover-account-status` returns `{ status: 'pending' }` while
    the owner is deciding.
  - `/recover-account-confirm` with `decision='approved'` finalizes
    (issues key, seals, transitions to `'ready'`).
  - `/recover-account-confirm` with `decision='denied'` fails the
    session.

If your agent SDK polls `/recover-account-status`, no client-side
change is needed — the SDK keeps polling until status flips to
`'completed'` or `'failed'`.

If your SaaS does not configure `owner_approval`, the existing
behavior is unchanged (no approval row exists, deny gate is a
no-op, /callback issues the key as before).

### 5. Session TTL for owner-approval-configured recoveries

Prior to the sweep, `/begin-registration` set
`agent_registration_sessions.expires_at = now() + 5m` for ALL kinds.
The reaper deletes sessions 1h past expiry. Owners had less than
1h to approve, even though `agent_recovery_approvals.expires_at` was
24h.

After the sweep, `emitOwnerApprovalRequest` GREATEST-bumps the
session `expires_at` to match the approval window (24h default).
A slow owner can still approve at hour 23 and the agent's session
won't have been reaped.

No code changes required — this is purely a behavior change inside
`emitOwnerApprovalRequest`.

### 6. New optional `kms` dep on /recover-account-confirm

The route handler's `RecoverAccountConfirmDeps` gained an optional
`kms?: KmsAdapter` field. Required only when the deferred-recovery
finalize path needs to run; otherwise omittable. See §2 above.

---

## What's NOT changing

- `req.agent` shape: same.
- Wire format of bearer tokens (`agk_<id>.<secret>`): same.
- Sealed-box format (libsodium `crypto_box_seal`): same.
- Audit-log columns: same (the canonical bytes formula is identical;
  only the per-day seed window changed in 0005).
- Public types exported from `@vouch/server`: additive only.
- Peer deps: same (pg, ioredis, libsodium, @aws-sdk/client-kms,
  @aws-sdk/client-s3 — all already pinned in v0.1).

---

## Testing your upgrade

1. Run the lib's own integration tests in your CI:
   ```sh
   npm run typecheck
   npm test
   npm run test:integration   # requires Docker for testcontainers
   npm run test:chaos
   npm run bench
   ```

2. Apply 0005 + 0006 to a staging DB.

3. If you configure `owner_approval`: run a recovery flow end-to-end
   (begin → callback → confirm) and verify the agent gets a usable
   key. The existing `test/integration/recover-deferred.int.test.ts`
   is a copy-pasteable template.

4. Tail audit log for the new event types:
   - `recover_callback_deferred_for_owner_approval` — emitted by
     /callback when it defers.
   - `recover_finalized_after_owner_approval` — emitted by
     /recover-account-confirm when it finalizes on approve.

---

## Rollback plan

If you need to roll back the post-v0.1 sweep:

1. Revert app deployment to the pre-sweep release tag.
2. Apply down-migrations:
   ```sh
   psql "$DATABASE_URL" \
     -f schema/migrations/0006_recover_pending_approval.down.sql \
     -f schema/migrations/0005_audit_chain_utc.down.sql
   ```
3. Pre-existing in-flight deferred-recovery sessions will be lost
   (their `awaiting_identity_id` references the now-dropped column);
   any agent SDK polling `/recover-account-status` for one will
   eventually time out. Re-run `/recover-account` from the SDK to
   re-issue.

The down-migrations are tested in CI via the migrations
forward+rollback round-trip.
