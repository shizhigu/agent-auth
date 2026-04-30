# agent-auth v8 spec — production-ready paying-customer (round-7 follow-up)

Round-7 graded B+/A-. v8 closes 5 must-fix + adds the production-grade items codex flagged.

## v8 must-fix items (round-7 blockers)

### MF-1: Recovery invariant (suspended)

v8 fixes contradiction: **Recovery requires `account.status = 'active'`**. Suspended accounts must be unsuspended via separate `/admin/unsuspend-account` flow before recovery. This is one invariant, no exceptions:

```ts
// Recovery flow
if (account.status === 'closed') return reject(410, 'account_closed')
if (account.status === 'suspended') return reject(403, 'account_suspended_unsuspend_first', {
  hint: 'Contact your SaaS admin to unsuspend before recovery.'
})
if (account.status !== 'active') return reject(500, 'unknown_account_status')  // fail-closed
```

Owner approval webhook fires BEFORE key issuance, not after:

```ts
// Within /callback for kind='recover':
1. Verify identity, check account binding, check reactivation eligibility
2. If config.recover_account.require_owner_approval:
   a. POST to approval_webhook_url with { account_id, identity_subject, request_id }
   b. Wait for /recover-account-confirm callback (or timeout 24h)
   c. If not approved: reject; identity stays revoked; no key issued
3. After approval (or if not required):
   a. Reactivate identity (per canReactivateIdentity rules)
   b. Issue new key
   c. Encrypt to client_pubkey
   d. Set session status='ready'
4. Old keys stay revoked (immutable)
```

### MF-2: Redis SET acceleration only, never correctness

```ts
async function invalidateAccountKeys(accountId: string) {
  // CORRECTNESS: always Postgres
  const dbResult = await db.query(
    `SELECT key_id FROM agent_api_keys
     WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')
     FOR UPDATE`,  // lock for atomicity with subsequent UPDATE
    [accountId]
  )
  const keyIds = dbResult.rows.map(r => r.key_id)

  // Mark all revoked in Postgres (single transaction, atomic)
  await db.query(
    `UPDATE agent_api_keys
     SET rotation_state = 'revoked', revoked_at = now(), revoked_reason = $2
     WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
    [accountId, 'account_invalidation']
  )

  // ACCELERATION: best-effort cache invalidation (Redis as accelerator)
  if (keyIds.length > 0) {
    const pipeline = redis.pipeline()
    for (const kid of keyIds) {
      pipeline.del(`agent-auth:key:${kid}`)
      pipeline.publish(`agent-auth:invalidate:key:${kid}`, '1')
    }
    pipeline.exec().catch(err => log.warn('cache_invalidation_failed', { err }))
  }
  // Redis SET is touched in normal flow but never queried for correctness
}
```

Validation middleware: cache miss falls through to Postgres always. Redis SET is read only by reconciliation job (acceleration) and per-key validation cache (per-request).

### MF-3: GitHub redelivery 3-day limit

GitHub docs: redelivery only available for past 3 days. v8 corrects:

```ts
agentAuth({
  reconciliation: {
    webhook_deliveries_poll_interval_seconds: 300,
    config_lookback_hours: 72,         // 3 days, GitHub limit
    config_max_pages: 10,
    fallback_active_revalidation: true   // see below
  }
})
```

**Fallback active revalidation** (handles >72h outage scenarios):

```ts
// On every key validation, if last_revalidated_at > 24h:
//   Enqueue async revalidation task
//   Revalidation calls GitHub /app/installations/<id>/access_tokens
//   Then calls /user with installation token to confirm app authorization
//   If user revoked app: cascade revoke

// This is a safety net for missed webhooks beyond 72h.
// Trade-off: extra API call per stale identity. Bounded by user activity.
```

If GitHub limit changes (e.g. extends to 7 days), config can be raised. Operator alert if attempting > GitHub max.

### MF-4: Emergency rotation synchronous invalidation

Emergency rotation (grace_seconds=0) MUST not depend on cache TTL:

```ts
async function emergencyRotate(oldKeyId: string, reason: string) {
  // Single transaction
  await db.transaction(async (tx) => {
    const old = await tx.queryOne(
      `SELECT * FROM agent_api_keys WHERE key_id = $1 AND rotation_state = 'active' FOR UPDATE`,
      [oldKeyId]
    )
    if (!old) throw new Error('key_not_active')

    const newKey = await issueNewKey(tx, old.account_id, old.issued_via_identity_id, ...)

    await tx.query(
      `UPDATE agent_api_keys
       SET rotation_state='revoked', revoked_at=now(), revoked_reason=$2,
           rotated_at=now(), rotation_grace_expires_at=now(),
           replaced_by_key_id=$3
       WHERE id=$1`,
      [old.id, `emergency_rotation: ${reason}`, newKey.id]
    )
  })

  // SYNCHRONOUS invalidation (await all): emergency means caller blocks for guarantee
  await Promise.all([
    redis.del(`agent-auth:key:${oldKeyId}`),
    redis.publish(`agent-auth:invalidate:key:${oldKeyId}`, '1'),
    waitForLocalCacheEviction(oldKeyId, 100)  // ms; subscribers ack via Redis pubsub
  ])

  // Audit
  await auditLog({ event: 'emergency_rotate', key_id: oldKeyId, reason })

  return { new_key: newKey }
}

async function waitForLocalCacheEviction(keyId: string, timeoutMs: number) {
  // Lib processes subscribe to invalidation channel and respond on a paired
  // 'agent-auth:invalidated' channel with their process_id.
  // Caller waits for N expected ack within timeout. If not all ack, log warning.
  // Cache TTL is the absolute backstop.
}
```

Additionally, every key validation cache entry includes `version` field. Lib maintains a Redis hash `agent-auth:revocation-version:<key_id>` updated on each revoke. Validation can opt-in (config flag) to check version on every request: cache hit + version match = ok; cache hit + version mismatch = miss → Postgres.

```ts
agentAuth({
  validation: {
    mode: 'cache_with_version_check' | 'cache_only_ttl',  // default: cache_only_ttl
    // version check adds 1 Redis GET per validation, gives sub-millisecond revocation
  }
})
```

### MF-5: DR semantics for rotations + revocations

```
Auth state durability tiers (configurable):
  Tier A — Standard (default): Postgres async streaming replication. RPO 5 min.
    OK for: account creation, identity verification, key issuance, planned rotation.
    NOT OK for: emergency revocations.
  Tier B — Critical: Postgres synchronous replication for specific tables.
    OK for: emergency revocations (await fsync on standby before client ack).
    Cost: higher latency on revoke ops, requires multi-AZ standby.

Per-operation tier mapping:
  POST /revoke (any reason)               → Tier B
  POST /rotate-key (grace_seconds = 0)    → Tier B
  Account suspension (cascade revokes)    → Tier B
  Identity revocation cascade             → Tier B
  Everything else                          → Tier A
```

Postgres `synchronous_commit = remote_apply` for Tier B writes. Lib uses `SET LOCAL synchronous_commit = remote_apply` per-statement for revocations.

If standby unreachable for Tier B write: operation fails closed (return 503). Client retries. Better than silent rollback after primary failover.

**Cross-region revocation log** (optional, for global SaaS):

```sql
CREATE TABLE agent_revocation_log (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  region TEXT NOT NULL,
  kind TEXT NOT NULL,                -- 'key_revoke' | 'account_suspend' | 'identity_revoke'
  target_id TEXT NOT NULL,           -- key_id or account_id or identity_id
  reason TEXT,
  replicated_to_regions TEXT[]       -- regions that have ack'd
);
```

Validation in any region checks `agent_revocation_log` (cross-region replicated via logical replication or app-layer). On replication lag > threshold, secondary region fails closed for writes, allows reads.

---

## v8 production-grade additions

### Admin CLI RBAC + MFA

```bash
# Admin operations require:
agent-auth admin <op> --auth-method oidc|webauthn|hmac --signed-by <admin-id>
```

Admin operations are NOT exposed as HTTP endpoints. They are CLI-only, requiring:
1. Local config file with admin OIDC issuer or webauthn registration
2. Per-operation MFA challenge (TOTP via local prompt, or webauthn)
3. Optional: two-person rule for destructive ops (require co-signer)

```yaml
# agent-auth-admin.yaml
admin:
  oidc_issuer: "https://accounts.google.com/o/saml2?idpid=..."
  required_mfa: webauthn
  two_person_required_for:
    - close-account
    - flush-cache
    - migrate-rollback
    - export-account
  audit_admin_ops: true
  approval_timeout_seconds: 600
```

Admin ops audit-logged with `event_type='admin_op'`, including admin identity, MFA method, co-signer if applicable.

### Immutable audit log

```sql
-- Hash chain: every audit row includes hash of previous row
ALTER TABLE agent_audit_log ADD COLUMN prev_hash BYTEA;
ALTER TABLE agent_audit_log ADD COLUMN row_hash BYTEA;

-- Computed on insert via trigger:
-- row_hash = SHA-256(prev_hash || canonical_json(row_excluding_hashes))

-- Retention: audit log is append-only by ROLE PERMISSIONS.
GRANT INSERT ON agent_audit_log TO agent_auth_app;
REVOKE UPDATE, DELETE ON agent_audit_log FROM agent_auth_app;
GRANT SELECT ON agent_audit_log TO agent_auth_admin;

-- Tamper detection job:
-- Hourly: walk recent audit rows, verify hash chain. Alert on break.
```

For SOC 2: weekly hash chain verification snapshot to S3 with object-lock. Quarterly tamper-evidence report.

### Expanded threat model (17 scenarios)

| # | Category | Scenario | Mitigation |
|---|---|---|---|
| RT-1 | Identity | Phishing user to authorize attacker GitHub App | Out of scope. SaaS UX clearly identifies app. |
| RT-2 | Session | Steal poll_token via XSS | Callback page has zero secrets, CSP enforced |
| RT-3 | Storage | Compromise Redis | Cache only, no plaintext secrets, 30s TTL bound |
| RT-4 | Storage | Compromise Postgres replica | Argon2id, HMAC IPs, PII minimized |
| RT-5 | Supply chain | npm pkg attack | Sigstore + npm provenance + SBOM attestation + SLSA L3 |
| RT-6 | Webhook | Replay GitHub webhook | HMAC verify + dedup + payload_hash mismatch alert |
| RT-7 | Memory | Steal API key from agent process | Outside lib boundary, leaked-prefix scanner mitigates |
| RT-8 | Spam | Time-based farming | Documented; warm tier doesn't unlock expensive ops |
| RT-9 | Tenancy | Cross-tenant access (BOLA) | Every query scoped by account_id; integration tests prove isolation |
| RT-10 | Admin | Privileged admin abuse | RBAC + MFA + two-person + audit log |
| RT-11 | Operator | Privileged operator misuse | Read-only by default; audit all DB-direct queries |
| RT-12 | Infrastructure | Postgres primary compromise | All admin ops audited; DB credentials short-lived; Vault/Sealed Secrets |
| RT-13 | Backup | Backup compromise | Backups encrypted at rest; restore requires multi-party authorization |
| RT-14 | CI/CD | Release pipeline compromise | OIDC trusted publishing; protected branches; two-person review on tags |
| RT-15 | DoS | Cost exhaustion attack | Per-IP/ASN rate limit; global emergency brake; alarm on cost spike |
| RT-16 | OAuth | Callback/session confusion | state= bound to session; PKCE verifier in DB only; exact redirect_uri |
| RT-17 | Audit | Audit log tampering | Hash chain + role permissions + S3 object-lock snapshots |
| RT-18 | DR | Failover race during rotation | Synchronous replication (Tier B) for revocations; cross-region log |

CI integration tests exercise each mitigation. Failure of any test blocks release.

### Expanded SOC 2 control mapping

```
CC6.1 (Logical access)
  - Authentication: OAuth + sealed-box delivery
  - Authorization: scope checks, tenant isolation
  - Audit: all access logged

CC6.2 (Logical access registration)
  - Identity registration: GitHub App OAuth + audience binding
  - Account creation: tied to verified identity
  - Periodic review: reconciliation job, identity revalidation

CC6.3 (Logical access modification/removal)
  - Key rotation: planned + emergency
  - Account suspension/closure
  - Identity revocation
  - All transitions logged immutable

CC6.6 (Logical credentials transmission)
  - Sealed box (X25519 + ChaCha20-Poly1305) for secret delivery
  - TLS 1.3 minimum for transport
  - Audit log scrubbing prevents secret leak in logs

CC7.1 (Detection: monitoring)
  - Metrics: registrations, validations, rate limits, webhook events
  - Alerts: cache hit drop, replay cap hit, reconciliation drift, identity reactivation spike

CC7.2 (Detection: anomaly)
  - Risk scoring per account
  - Behavior fingerprinting
  - Leaked-prefix scanner (GitHub search)

CC7.3 (Evaluation: incidents)
  - Runbook RB-1 through RB-7
  - Incident severity matrix
  - Customer notification SLA: 24h for breach affecting customer keys

CC7.4 (Response: incidents)
  - Force-revoke key (RB-1)
  - Suspend account (RB-2)
  - Flush cache (RB-4)
  - Force webhook reconciliation (RB-3)

CC7.5 (Recovery: incidents)
  - Restore from PITR
  - Identity unblock (RB-5)
  - DR drill quarterly

CC8.1 (Change management)
  - Forward-compatible migrations
  - Two-deploy destructive change protocol
  - Schema version pinned to lib version

CC9.2 (Vendor risk)
  - Pinned deps + npm audit
  - GitHub App scope minimization
  - Anthropic API key never stored
  - Annual vendor security review
```

Confidentiality / Privacy criteria covered if SaaS opts in.

### Multi-region with explicit thresholds

```yaml
multi_region:
  primary_region: us-east-1
  secondary_regions:
    - us-west-2:
        replica_lag_threshold_seconds: 30
        on_threshold_exceeded: fail_closed_writes
    - eu-west-1:
        replica_lag_threshold_seconds: 30
        on_threshold_exceeded: route_to_primary
  validation_freshness_required:
    revocation: 1   # second; if cross-region log lag > 1s, fail validation
    issuance: 30    # second; can serve key validation 30s old in stale region
```

Lib enforces threshold via dual queries (cross-region log lag check + main validation). Replica lag exceeded → fail closed.

### Performance budget split

```
Validation latency targets:

Cache hit (same AZ as Redis):
  P50: 1ms, P99: 5ms
Cache miss → Postgres read (same AZ):
  P50: 10ms, P99: 50ms
Cross-AZ (Redis or Postgres in different AZ):
  P50: 5ms (cache hit), 30ms (cache miss); P99: 20ms / 100ms
Cross-region (DR fallback):
  P50: 50ms, P99: 200ms; degraded mode

Argon2id verification (params m=64MB, t=3, p=4):
  ~30ms on commodity hardware. Cached after first verify per request.
```

Argon2id is on cache miss only. Cache stores `argon2id_verified=true` with key hash to avoid repeated verify within TTL window.

### Disaster recovery — exact semantics

```
Operations and their durability tier:
  Account create/update         → Tier A (5 min RPO)
  Identity create/update         → Tier A
  Key issue (planned)            → Tier A
  Key rotate (planned, grace>0)  → Tier A
  Key rotate (emergency, grace=0)→ Tier B (synchronous replication)
  Key revoke                     → Tier B
  Account suspend                → Tier B
  Identity revoke (cascade)      → Tier B

Failover decision tree:
  1. Is replication lag < threshold? Yes: failover safe.
  2. Lag > threshold but < 5x: failover possible, log "potential rollback risk"
  3. Lag > 5x threshold: manual decision, alert oncall.
  4. Primary down + lag unknown: fail open (refuse failover) until investigation.

Specifically for revocations:
  Tier B writes await fsync on standby. If standby unreachable:
    - Lib returns 503 'durability_unavailable'
    - Client retries with exponential backoff
    - Operations team alerted
    - Better than silent rollback risk
```

### Supply chain hardening

```yaml
release:
  npm_trusted_publishing: true        # OIDC, no long-lived NPM_TOKEN
  protected_release_tags: true        # require two reviewers on git tag
  protected_environments: true        # release env requires manual approval
  signing:
    method: sigstore
    sbom_attestation: true            # SLSA L3
    signed_by_keys:
      - /tags/v*: required-reviewers   # multi-signer
  scanning:
    secret_scanning: true
    dependency_review: true
    openssf_scorecard: true
    minimum_scorecard: 8.0            # block release < 8.0
  reproducible_build: target          # SLSA L3 requires reproducible
  consumer_verification:
    method: npm-provenance OR cosign-verify-blob-attestation
    docs: README.md#verifying-releases
```

### Deprecation/Sunset (RFC compliance)

```
HTTP responses for deprecated endpoints include:
  Deprecation: @1730419200          ; RFC 9745
  Sunset: Sat, 01 Apr 2027 00:00:00 GMT  ; RFC 8594
  Link: <https://docs.../v2-migration>; rel="deprecation"

Security exception: CVE-driven breakage allowed with:
  - 30-day notice (vs 12-month standard)
  - Patch version on old + new
  - Coordinated disclosure if relevant
```

### GDPR — configurable retention

```yaml
gdpr:
  retention:
    audit_log:
      jurisdictions:
        eu: 365_days_pseudonymized
        us: 730_days
        default: 365_days
      pseudonymization:
        method: hmac_with_rotation  # rotate hmac key annually
        retained_fields: [event_type, ts, status_class]
        nullified_fields: [ip_hash, user_agent, account_id]   # after retention period
    backups:
      include_in_erasure: true       # erasure operations propagate to backups via tombstone
  legal_basis:
    audit_log: legitimate_interest_security  # GDPR Article 6(1)(f)
    retention_extension: legal_obligation_or_claims  # Article 17(3)(b/e)
```

Erasure flow:
1. SaaS owner calls `/api/agent-auth/account/<id>/erase` with reason
2. Active session: nullify PII fields (display_handle, identities.display_handle)
3. Audit log: pseudonymize per jurisdiction
4. Backup tombstone: written to S3 list of erased account IDs
5. Quarterly backup-purge job applies tombstones to backup retention

---

## Round-8 audit questions

1. Are MF-1 through MF-5 now correctly invariant + production-grade?

2. Tier A vs Tier B durability: any operation classified wrong? Any operation that needs Tier C (synchronous + cross-region)?

3. Threat model now 17 scenarios. Still missing? Are any over-claimed (mitigation insufficient)?

4. SOC 2 mapping expanded. Is CC6.6 now correctly framed? Any control still mis-mapped?

5. Multi-region thresholds (30s default, 1s for revocation cross-region log). Realistic for production deployment? Too lax / too strict?

6. Performance split with Argon2id ~30ms on cache miss. Is the cache-miss budget realistic, given that cache misses can be high during cold start or after invalidation storms?

7. Supply chain: SLSA L3 + reproducible build target + Scorecard ≥ 8.0 + npm Trusted Publishing. Production-grade or still gaps?

8. GDPR retention with HMAC pseudonymization and annual key rotation. Defensible to a DPO audit, or further tightening needed?

9. Admin CLI design: CLI-only (no HTTP), MFA, two-person rule. Is this production-ready, or do we need: hardware token requirement, time-of-day restrictions, geo-fencing?

10. Final grade. Is v8 now production-ready paying-customer level (codex grade A or A+), or is there still daylight?

11. If still gaps: list the EXACT remaining items (not categories) that would block a CISO/SOC 2 auditor sign-off.
