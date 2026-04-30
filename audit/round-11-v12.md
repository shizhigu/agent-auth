# agent-auth v12 — final narrow patch (10 items to A)

Round-11: A-, codex says one narrow iteration closes A. v12 only addresses the 10 listed items, no scope expansion.

## 10 round-11 items

### LSN-1: Post-commit barrier LSN, not column default

```sql
-- Drop wrong default
ALTER TABLE agent_revocation_log ALTER COLUMN commit_lsn DROP DEFAULT;

-- Lib captures commit LSN AFTER tx commits
```

```ts
async function tierBRevoke(...) {
  let commitLsn: string
  await db.transaction(async (tx) => {
    tx.set('synchronous_commit', 'remote_apply')
    await tx.query(`UPDATE agent_api_keys SET rotation_state='revoked', ... WHERE ...`)
    await tx.query(`INSERT INTO agent_revocation_log (..., commit_lsn) VALUES (..., '0/0')`)
    // commit_lsn placeholder; updated immediately after commit
  })
  // After commit: capture the LSN this tx is durable at
  commitLsn = (await db.query(`SELECT pg_current_wal_insert_lsn() AS lsn`)).rows[0].lsn
  await db.query(
    `UPDATE agent_revocation_log SET commit_lsn = $1 WHERE target_id = $2 AND commit_lsn = '0/0'`,
    [commitLsn, keyId]
  )

  // Also bump global revocation barrier
  await db.query(
    `INSERT INTO agent_revocation_barrier (id, last_lsn) VALUES (1, $1)
     ON CONFLICT (id) DO UPDATE SET last_lsn = GREATEST(agent_revocation_barrier.last_lsn, $1)`,
    [commitLsn]
  )
}
```

```sql
-- Singleton barrier table
CREATE TABLE agent_revocation_barrier (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_lsn pg_lsn NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO agent_revocation_barrier (id, last_lsn) VALUES (1, '0/0');
```

### LSN-2: Global replay barrier as primary correctness gate

```ts
async function validateInSecondaryRegion(keyId: string) {
  // 1. Read GLOBAL barrier from local replica
  const barrier = await localDb.queryOne(
    `SELECT last_lsn FROM agent_revocation_barrier WHERE id = 1`
  )
  // 2. Read replica's replay position
  const replayPos = await localDb.queryOne(`SELECT pg_last_wal_replay_lsn() AS lsn`)

  if (replayPos.lsn === null) {
    // We are on primary or replication broken. Different logic.
    return await primaryValidate(keyId)
  }

  // 3. Correctness gate: replica must have replayed AT LEAST the global barrier
  if (pg_lsn_compare(replayPos.lsn, barrier.last_lsn) < 0) {
    if (config.on_lag === 'fail_closed') return reject(503, 'region_replication_stale')
    if (config.on_lag === 'route_to_primary') return await primaryValidate(keyId)
  }

  // 4. Now we can trust local read (we know all revokes up to barrier are visible)
  return await runStandardValidation(keyId)
}
```

### LSN-3: Per-key last_revoke_lsn as optimization

`last_revoke_lsn` on the key row is now an OPTIMIZATION (allows fine-grained barrier per-key). Correctness still requires global barrier. Comment in spec:

```sql
COMMENT ON COLUMN agent_api_keys.last_revoke_lsn IS
  'Optimization: per-key barrier. NOT a correctness gate.
   Correctness uses agent_revocation_barrier.last_lsn (global).';
```

### LSN-4: NULL pg_last_wal_replay_lsn handling

```ts
// On primary: pg_last_wal_replay_lsn() returns NULL (no replay happening)
// On secondary: returns the replay position
// If NULL on what we think is secondary: misconfiguration → fail closed

const replayPos = await localDb.queryOne(`SELECT pg_last_wal_replay_lsn() AS lsn`)
if (replayPos.lsn === null) {
  if (config.role === 'secondary') {
    log.alert('replication_broken_or_misconfigured')
    if (config.on_replication_broken === 'fail_closed') return reject(503, 'replication_broken')
    return await primaryValidate(keyId)
  }
  // role === 'primary': skip barrier check, use direct read
}
```

### LSN-5: LSN timeline / failover handling

```sql
ALTER TABLE agent_revocation_barrier
  ADD COLUMN timeline_id INT NOT NULL DEFAULT 1;
```

```ts
async function getCurrentTimeline(): Promise<number> {
  const r = await localDb.queryOne(
    `SELECT timeline_id FROM pg_control_checkpoint()`
  )
  return r.timeline_id
}

async function validateInSecondaryRegion(keyId: string) {
  const localTimeline = await getCurrentTimeline()
  const barrier = await localDb.queryOne(
    `SELECT last_lsn, timeline_id FROM agent_revocation_barrier WHERE id = 1`
  )
  if (barrier.timeline_id !== localTimeline) {
    // Failover happened: barrier is from previous timeline
    log.alert('lsn_timeline_mismatch_post_failover')
    return reject(503, 'failover_in_progress')
    // Operator runbook: after promotion, run `agent-auth admin reset-barrier`
    // which captures fresh barrier on new timeline.
  }
  // ... rest as before
}
```

Operator runbook addition (RB-8):
```bash
agent-auth admin reset-barrier
# Issued after promotion; captures pg_current_wal_insert_lsn() on new timeline,
# updates agent_revocation_barrier.timeline_id and last_lsn.
# Service resumes after reset.
```

### IDEM-1: resource_ref in Phase 1

```sql
ALTER TABLE agent_idempotency
  ADD COLUMN operation_type TEXT NOT NULL,        -- 'revoke' | 'rotate' | 'register' | ...
  ADD COLUMN resource_ref TEXT NOT NULL,          -- 'key:<key_id>' | 'rotation:<old_id>:<new_id>'
  ADD COLUMN reconcile_attempts INT NOT NULL DEFAULT 0,
  ADD COLUMN last_reconcile_at TIMESTAMPTZ,
  ADD COLUMN manual_required_at TIMESTAMPTZ;
```

```ts
async function tierBIdempotent(
  idemKey: string,
  requestHash: Buffer,
  operationType: string,
  resourceRef: string,                              // computed BEFORE Phase 1
  operation: () => Promise<...>
) {
  // Phase 1 stores operation_type + resource_ref durably
  await db.query(
    `INSERT INTO agent_idempotency (key, request_hash, operation_type, resource_ref, state, expires_at)
     VALUES ($1, $2, $3, $4, 'pending', now() + interval '24 hours')`,
    [idemKey, requestHash, operationType, resourceRef]
  )
  // Phase 2 as before
}
```

resource_ref must be deterministic from input. For revoke: `key:<key_id>`. For rotation: `rotation:<old_id>` (then on success, the new key_id is captured into outcome_body).

### IDEM-2: terminal manual_required state

```sql
ALTER TABLE agent_idempotency
  DROP CONSTRAINT IF EXISTS agent_idempotency_state_check;
ALTER TABLE agent_idempotency
  ADD CONSTRAINT agent_idempotency_state_check CHECK (
    state IN ('pending','completed','failed','unknown','manual_required')
  );
```

```ts
async function reconcileUnknownIdempotency() {
  const stale = await db.query(
    `SELECT * FROM agent_idempotency
     WHERE state IN ('pending','unknown')
       AND created_at < now() - interval '5 minutes'
       AND state != 'manual_required'`
  )

  for (const row of stale.rows) {
    if (row.reconcile_attempts >= 5 ||
        (row.last_reconcile_at && now - row.last_reconcile_at > 30min)) {
      await db.query(
        `UPDATE agent_idempotency
         SET state='manual_required', manual_required_at=now()
         WHERE key=$1 AND state IN ('pending','unknown')`,
        [row.key]
      )
      log.alert('idempotency_manual_required', {
        key: row.key, op: row.operation_type, ref: row.resource_ref
      })
      pageOncall('idempotency_manual_required', { key: row.key })
      continue
    }

    const actualState = await checkResourceState(row.operation_type, row.resource_ref)
    await db.query(
      `UPDATE agent_idempotency
       SET reconcile_attempts = reconcile_attempts + 1,
           last_reconcile_at = now()
       WHERE key = $1`,
      [row.key]
    )

    if (actualState === 'committed') {
      await transitionToCompleted(row.key, await reconstructResponse(row))
    } else if (actualState === 'not_found') {
      await transitionToFailed(row.key, { error: 'commit_lost' })
    }
    // else: unknown — try again next observer pass, increments counter
  }
}
```

### IDEM-3: Monotonic state transitions

```sql
-- State transitions are append-only via constraint
CREATE FUNCTION enforce_idempotency_monotonic() RETURNS TRIGGER AS $$
BEGIN
  -- Allowed transitions:
  --   NULL (insert) → pending
  --   pending → completed | failed | unknown
  --   unknown → completed | failed | manual_required
  --   completed → completed (idempotent retry)
  --   failed → failed (idempotent retry)
  --   manual_required → manual_required (terminal until admin)
  -- DISALLOWED: completed → anything else, failed → anything else (except admin manual)

  IF OLD.state IN ('completed','failed','manual_required') AND NEW.state != OLD.state THEN
    -- Allow admin override only with specific role
    IF current_user != 'agent_auth_admin' THEN
      RAISE EXCEPTION 'idempotency_state_regression_blocked: % → %', OLD.state, NEW.state;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_idempotency_monotonic
BEFORE UPDATE OF state ON agent_idempotency
FOR EACH ROW EXECUTE FUNCTION enforce_idempotency_monotonic();
```

Timeout handlers cannot regress completed back to unknown. Reconciliation observer cannot regress completed back to pending. Admin role required for forced override.

### GDPR-1: Citation split

```yaml
gdpr_legal_basis:
  audit_log_retention:
    legal_obligation_basis: GDPR Article 17(3)(b)        # legal obligations
    legal_claims_basis: GDPR Article 17(3)(e)            # establishment, exercise, defense of legal claims
    security_legitimate_interest: GDPR Article 6(1)(f) + Recital 49
  documentation_required:
    LIA: docs/gdpr/lia.md (legitimate interest assessment)
    DPIA: docs/gdpr/dpia.md (data protection impact assessment)
    ROPA: docs/gdpr/ropa.md (record of processing activities)
```

### GDPR-2: Per-subject crypto-erasure key material

```yaml
crypto_erasure:
  pepper_strategy: per_subject
  storage:
    keys: KMS-managed, one per subject (or per-cohort with subject-id-derived KDF)
    key_format: "subject:<account_id_hash>"
    rotation: annual  # or on-demand
  on_erasure:
    method: KMS schedule_key_deletion(subject_kms_key_id, pending_window=30_days)
    irrevocable_after: 30_day_window
    verification: post-deletion attestation in audit log
  shared_pepper_FALLBACK:
    available: true
    when: high-volume SaaS where per-subject key is impractical
    trade-off: erasure is "best effort minimization" not crypto-erasure
    documented_to: SaaS owner's DPO
    requires_explicit_opt_in: true
```

Implementation:
```ts
async function pseudonymize(subjectId: string, value: string): Promise<string> {
  const kmsKey = await getOrCreateSubjectKmsKey(subjectId)
  const hmac = await kms.generateMac({ KeyId: kmsKey.id, Message: Buffer.from(value), MacAlgorithm: 'HMAC_SHA_256' })
  return base64url(hmac.Mac)
}

async function eraseSubject(subjectId: string) {
  const kmsKey = await getSubjectKmsKey(subjectId)
  await kms.scheduleKeyDeletion({ KeyId: kmsKey.id, PendingWindowInDays: 30 })
  // After 30 days, key cannot be recovered. Pseudonymized values become unlinkable.
  // Audit log writes attestation of deletion.
}
```

Per-subject KMS keys are expensive at scale. SaaS owner can opt for shared-pepper if they accept that "erasure" is "minimization" not crypto-erasure. Lib documents both clearly.

---

## Round-12 audit questions (final)

1. Are all 10 round-11 items now closed at correctness level?

2. The LSN barrier with timeline_id handling: is there any failover scenario where it could fail to reset properly?

3. Idempotency monotonic state transitions: any operation paths where this trigger blocks legitimate work?

4. Per-subject crypto-erasure: KMS key per subject is expensive. Is the documented shared-pepper fallback acceptable for paying customers, or is it a deal-breaker for SOC 2?

5. Final grade. Is this A spec now? Production-ready paying-customer at design level?

6. Last item: any remaining MUST-FIX items or are we at the spec ceiling?
