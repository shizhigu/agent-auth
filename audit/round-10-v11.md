# agent-auth v11 — close round-10 A blockers

Round-10: high A-. v11 closes 4 specific blockers + 10 threats + revalidation UX. Goal: A spec.

## 4 round-10 blockers

### B-α': Monotonic Redis epoch via Lua MAX

```lua
-- redis-epoch-update.lua
local key = KEYS[1]
local proposed = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', key) or '0')
if proposed > current then
  redis.call('SET', key, proposed)
  return proposed
end
return current
```

```ts
async function bumpRevocationEpoch(newEpoch: number): Promise<number> {
  const result = await redis.eval(EPOCH_UPDATE_SCRIPT, 1, 'agent-auth:revocation-epoch', newEpoch)
  if (result < newEpoch) {
    log.warn('redis_epoch_already_higher', { proposed: newEpoch, observed: result })
    // OK: another concurrent revoke wrote a later epoch. DB is authoritative.
  }
  return result
}
```

For Redis quorum visibility: WAIT command after SET ensures replication to N replicas:

```ts
await redis.eval(EPOCH_UPDATE_SCRIPT, 1, key, newEpoch)
const replicaAcks = await redis.wait(config.redis_replica_quorum, 1000)  // wait up to 1s
if (replicaAcks < config.redis_replica_quorum) {
  log.alert('redis_quorum_unavailable_during_revoke')
  // Lib still proceeds: DB is authoritative. Validation falls through to DB on epoch mismatch.
  // But emit metric for ops team.
}
```

### B-β': LSN-based correctness (not byte-lag)

Each Tier B commit captures its commit LSN. Validation in secondary region requires local replica has consumed AT LEAST that LSN.

```sql
-- Updated agent_revocation_log
ALTER TABLE agent_revocation_log
  ADD COLUMN commit_lsn pg_lsn NOT NULL DEFAULT pg_current_wal_lsn();

-- And: every key has its last revoke commit LSN tracked
ALTER TABLE agent_api_keys
  ADD COLUMN last_revoke_lsn pg_lsn;
```

```ts
async function validateInSecondaryRegion(keyId: string) {
  // 1. Look up key
  const row = await localDb.queryOne(`SELECT * FROM agent_api_keys WHERE key_id = $1`, [keyId])
  if (!row) return reject(401, 'key_not_found')

  // 2. If we have a last_revoke_lsn for this key, check local replica caught up
  if (row.last_revoke_lsn) {
    const localPosition = await localDb.queryOne(`SELECT pg_last_wal_replay_lsn() AS lsn`)
    if (pg_lsn_compare(localPosition.lsn, row.last_revoke_lsn) < 0) {
      // Local replica is behind the LSN at which key was revoked.
      // Cannot serve correctness; route to primary or fail closed.
      if (config.on_lag === 'fail_closed') return reject(503, 'region_replication_stale')
      return await primaryDb.validate(keyId)
    }
  }
  // 3. Standard validation
  return await runStandardValidation(row)
}
```

This is actual correctness: validation cannot reject a revoked key only if local LSN < revoke LSN, in which case we route or fail.

### B-γ': Durable pre-transaction reservation + automated reconciliation

```ts
// Two-phase idempotency:
// Phase 1 (separate tx): reserve idempotency row pending
// Phase 2 (Tier B tx): execute operation, finalize state via observer

async function tierBIdempotent<T>(
  idemKey: string,
  requestHash: Buffer,
  operation: (tx: DBTransaction) => Promise<{ status: number, body: T, resourceRef: string }>
): Promise<{ status: number, body: T }> {
  // Phase 1: reservation in own transaction (durably committed)
  const reserved = await db.transaction(async (tx) => {
    const existing = await tx.queryOne(
      `SELECT * FROM agent_idempotency WHERE key = $1 FOR UPDATE`,
      [idemKey]
    )
    if (existing) {
      if (!constantTimeEqual(existing.request_hash, requestHash)) {
        throw new IdempotencyMismatchError()
      }
      return { existing }
    }
    await tx.query(
      `INSERT INTO agent_idempotency (key, request_hash, state, expires_at)
       VALUES ($1, $2, 'pending', now() + interval '24 hours')`,
      [idemKey, requestHash]
    )
    return { existing: null }
  })

  if (reserved.existing?.state === 'completed' || reserved.existing?.state === 'failed') {
    return reserved.existing
  }
  if (reserved.existing?.state === 'pending') {
    return reject(425, 'idempotency_in_flight', { retry_after: 1 })
  }
  if (reserved.existing?.state === 'unknown') {
    // Observer should have reconciled. If still unknown, manual.
    return reject(503, 'idempotency_unknown_outcome')
  }

  // Phase 2: actual operation in separate Tier B transaction
  let result: { status: number, body: T, resourceRef: string }
  try {
    result = await db.tierBTransaction(operation)
    await db.query(
      `UPDATE agent_idempotency
       SET state='completed', outcome_status=$2, outcome_body=$3, resource_ref=$4
       WHERE key=$1`,
      [idemKey, result.status, result.body, result.resourceRef]
    )
  } catch (err) {
    if (err instanceof TierBTimeoutError) {
      // Don't mark failed; mark unknown. Observer will reconcile.
      await db.query(
        `UPDATE agent_idempotency SET state='unknown' WHERE key=$1`,
        [idemKey]
      )
      throw err  // 503 to caller
    }
    await db.query(
      `UPDATE agent_idempotency SET state='failed', outcome_status=$2, outcome_body=$3
       WHERE key=$1`,
      [idemKey, errorStatus(err), errorBody(err)]
    )
    throw err
  }
  return result
}
```

**Automated reconciliation observer** (background job, every 60s):

```ts
async function reconcileUnknownIdempotency() {
  const stale = await db.query(
    `SELECT * FROM agent_idempotency
     WHERE state IN ('pending', 'unknown') AND created_at < now() - interval '5 minutes'`
  )

  for (const row of stale.rows) {
    // resource_ref tells us what to look up. Examples:
    //   'key:agk_aB1cD2eF' → check if agent_api_keys row exists
    //   'rotation:from:agk_xxx' → check if successor was created
    //   'revoke:agk_yyy' → check if rotation_state='revoked'
    const actualState = await checkResourceState(row.resource_ref)

    if (actualState === 'committed') {
      await db.query(
        `UPDATE agent_idempotency SET state='completed', outcome_status=200, outcome_body=$2
         WHERE key=$1`, [row.key, await reconstructResponse(row.resource_ref)]
      )
    } else if (actualState === 'not_found') {
      await db.query(
        `UPDATE agent_idempotency SET state='failed', outcome_status=503, outcome_body=$2
         WHERE key=$1`, [row.key, { error: 'commit_lost' }]
      )
    } else {
      // Cannot determine. Page oncall.
      log.alert('idempotency_unreconcilable', { key: row.key, resource_ref: row.resource_ref })
    }
  }
}
```

### B-δ': Webhook signature ordering + atomic nonce

```ts
async function verifyAndDedupWebhook(req: WebhookRequest, secret: Buffer): Promise<'verified' | 'invalid'> {
  // 1. Validate header presence & length (cheap, fail fast on garbage)
  const sig = req.headers['x-agent-auth-signature']
  const ts = req.headers['x-agent-auth-timestamp']
  const nonce = req.headers['x-agent-auth-nonce']
  if (!sig || sig.length !== 64) return 'invalid'  // hex SHA-256 = 64 chars
  if (!ts || !/^\d+$/.test(ts)) return 'invalid'
  if (!nonce || nonce.length !== 44) return 'invalid'  // base64 256-bit = 44 chars

  // 2. Timestamp skew check
  if (Math.abs(Date.now() / 1000 - parseInt(ts)) > 300) return 'invalid'

  // 3. Verify HMAC FIRST (no state mutation yet)
  const canonical = canonicalize(req)
  const expected = hmacSha256(secret, canonical).toString('hex')
  if (!constantTimeEqual(expected, sig)) return 'invalid'

  // 4. AFTER verify: atomic nonce check via SET NX EX
  const reserved = await redis.set(
    `agent-auth:webhook-nonce:${nonce}`, '1',
    'EX', 600, 'NX'
  )
  if (!reserved) return 'invalid'  // nonce already seen

  return 'verified'
}
```

Order: cheap validation → timestamp → HMAC → atomic nonce reservation. Invalid traffic cannot fill nonce storage because it fails before nonce reservation.

`SET NX EX` is atomic in Redis, native single-command primitive.

## Round-10 other items

### Revalidation UX with policy tiers

```yaml
revalidation:
  policies:
    default:
      cadence_days: 14
      forced_on_webhook_revoke: true
      forced_on_suspicious_activity: true
    high_risk:                       # admin-tier scopes, hot tier
      cadence_days: 1
      forced_on_webhook_revoke: true
      forced_on_privilege_escalation: true
    sensitive_endpoint_per_call:     # specific high-value endpoints
      revalidate_per_call: true
```

Default 14d (was 24h). 24h reserved for high-risk/admin/Tier B scopes. Per-call revalidation for sensitive endpoints (e.g. cross-tenant data access, payment ops).

### 10 additional threat scenarios

| # | Scenario | Mitigation |
|---|---|---|
| RT-35 | Supply-chain compromise (transitive npm dep) | Pinned + lockfile + scorecard ≥ 8.5 + manual review for new transitive |
| RT-36 | CI/CD credential abuse (compromised GitHub token) | Trusted publishing OIDC; protected branches; ephemeral tokens; OIDC audience binding |
| RT-37 | KMS key deletion / policy takeover | KMS admin in separate AWS account, two-person; key deletion 7-day waiting period; CloudTrail alarms |
| RT-38 | SSO/IdP compromise (admin SSO) | Independent break-glass admin path; audit SSO logins; periodic SSO config attestation |
| RT-39 | Audit event omission by compromised app | Outbox pattern + reconciliation observer + WORM external audit; missing events trigger alarm |
| RT-40 | Backup restore revocation rollback | Post-restore tombstone reapply procedure + integration test; revocation log replayed from cross-region log |
| RT-41 | Recovery approver compromise | Two-person rule for high-value recovery; approval webhook signature with rotating secret; post-approval audit alert |
| RT-42 | Webhook secret rotation race | Dual-secret support during rotation: lib accepts both old + new for 24h; Redis SET tracks active secrets |
| RT-43 | Fail-closed DoS amplification | Circuit breaker on fail-closed paths: if X% requests fail-closed in 1min, switch to degraded mode (best-effort) with operator alert |
| RT-44 | Observability/APM secret leakage | OTEL exporter scrubs span attrs; metric labels never include subjects/keys; explicit allowlist |

Total: 44 scenarios.

### GDPR framing tightened

```yaml
gdpr_statement:
  active_systems_erasure:
    method: nullification + tombstone
    completion_window_days: 30
  worm_audit_record:
    classification: pseudonymized_personal_data  # remains personal data per EDPB
    legal_basis_for_retention: GDPR Article 17(3)(b) (legal obligation/claims)
    minimization: only HMAC'd identifiers + event metadata, no direct PII
    crypto_erasure_on_request:
      destroy: HMAC pepper used for this subject
      result: pseudonymized record becomes unlinkable to subject
      legal_framing: "additional information needed to re-identify destroyed; record approaches anonymous within reasonable means"
      important_note: "Lib does not represent this as GDPR-defined complete erasure. SaaS owner's DPO and legal must confirm whether this satisfies their jurisdiction's interpretation."
  retention_documentation:
    LIA: docs/gdpr/lia.md
    DPIA: docs/gdpr/dpia.md
    ROPA: docs/gdpr/ropa.md
```

Lib-shipped docs are templates. SaaS owner customizes for their specific deployment + legal context.

---

## Round-11 audit questions

1. Are the 4 round-10 blockers (epoch monotonic, LSN correctness, durable pre-tx idempotency, atomic nonce) now closed at correctness level?

2. Reconciliation observer: any failure mode where state stays 'unknown' indefinitely?

3. Revalidation cadence configurable per policy: defensible UX for paying customers? Any policy I'm missing?

4. 44 threats. Now sufficient for CISO sign-off?

5. GDPR framing acknowledges lib does not represent crypto-erasure as Article 17 complete erasure. Sufficient legal positioning?

6. Final grade. Production-ready paying-customer? At A spec ceiling now?

7. If still gaps to A: list EXACT remaining items (not categories).

8. We've done 11 rounds. Diminishing returns? Or one more iteration warranted?
