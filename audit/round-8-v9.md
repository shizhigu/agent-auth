# agent-auth v9 — close round-8 signoff blockers

Round-8 graded A-/A with 9 specific blockers. v9 closes each. Goal: A or A+ CISO-ready.

## Closing the 9 signoff blockers

### B-1: GitHub fallback revalidation rewrite

User-authorization status cannot be checked with installation token. v9 uses two paths:

**Path 1 (preferred): forced fresh OAuth on next activity**
After `last_revalidated_at` > 24h, the next API call from the agent triggers async revalidation. Revalidation = lib generates new poll_token, returns 401 with header `WWW-Authenticate: AgentAuth realm="reauth", challenge_url="..."`. Agent SDK catches this, runs OAuth flow silently (browser flow with prompt=none if SSO session valid; otherwise device flow). On success, identity row's `last_revalidated_at = now()`.

**Path 2 (optional): persisted encrypted user token for revalidation**
SaaS owner opts in via `revalidation: { method: 'persisted_user_token' }`. Lib stores OAuth refresh_token encrypted (KMS-backed envelope). On revalidation cadence, exchange refresh → access → call /user. If 401 from GitHub, mark identity revoked. Trade-off: stores user creds, must comply with vault standards. Only for SaaS that need passive revalidation.

Default = Path 1. Path 2 documented but disabled by default.

```yaml
revalidation:
  method: forced_fresh_oauth_on_activity   # or persisted_user_token
  cadence_hours: 24
  storage:
    encryption_kms_key: arn:aws:kms:...    # required if persisted_user_token
```

### B-2: Emergency revocation independent of pubsub+TTL (mandatory)

```ts
agentAuth({
  validation: {
    mode: 'revocation_epoch_check'  // MANDATORY for production
    // 'cache_only_ttl' is now opt-in for non-production only
  }
})
```

Implementation: every key validation does ONE Redis GET to fetch the global revocation epoch. If epoch changed since cache entry was made, force Postgres re-check.

```sql
-- Revocation epoch: monotonic counter incremented on any revoke
CREATE TABLE agent_revocation_epoch (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- singleton
  epoch BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO agent_revocation_epoch (id, epoch) VALUES (1, 0);
```

```ts
// On any revoke:
await db.query(`UPDATE agent_revocation_epoch SET epoch = epoch + 1, updated_at = now()`)
await redis.set('agent-auth:revocation-epoch', currentEpoch)

// On validation:
const cachedEpoch = cache.epoch_at_cache
const currentEpoch = await redis.get('agent-auth:revocation-epoch')  // O(1)
if (cachedEpoch !== currentEpoch) {
  // Cache stale, force Postgres re-check
  cache = await fetchKeyFromDb(keyId)
}
// Then standard validation
```

Cost: 1 extra Redis GET per validation (~0.5ms same-AZ). Worth it for sub-millisecond emergency revocation guarantee.

### B-3: Tier B commit timeout + unknown-outcome

```ts
async function tierBCommit(operation: () => Promise<T>): Promise<T> {
  const COMMIT_TIMEOUT_MS = 5000

  try {
    return await Promise.race([
      operation(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new TierBTimeoutError()), COMMIT_TIMEOUT_MS)
      )
    ])
  } catch (err) {
    if (err instanceof TierBTimeoutError) {
      // Outcome unknown: commit may have succeeded on primary but standby unconfirmed
      log.alert('tier_b_unknown_outcome', { op: operation.name })
      // 1. Return 503 to client with idempotency hint
      // 2. Page oncall
      // 3. Lib emits metric agent_auth_tier_b_unknown_outcome_total
      throw new ServiceUnavailableError('durability_unconfirmed', {
        retry_with: getIdempotencyKey()
      })
    }
    if (err.code === 'XX098' /* postgres synchronous_commit failed */) {
      log.alert('tier_b_standby_unreachable')
      throw new ServiceUnavailableError('durability_unavailable')
    }
    throw err
  }
}
```

Idempotency: every Tier B operation requires `Idempotency-Key` header from client. Lib tracks recent idempotency keys 24h. Retry with same key returns same response (success or failure). Avoids double-revoke or duplicate key issuance.

### B-4: close-account + erase to Tier B

```
Updated tier mapping:
  Tier A:
    Account create
    Identity create
    Key issue (planned)
    Key rotate (planned, grace > 0)
  Tier B:
    Key revoke (any reason)
    Key rotate (emergency, grace = 0)
    Account suspend (cascades to revokes)
    Account close (cascades to revokes; irreversible)
    Account erase (cascades to revokes; irreversible)
    Identity revoke (cascade to keys)
    Cross-region revocation log write (paired with revoke in same tx)
```

Account erase:
1. Tier B: revoke all keys + identities for account (atomic)
2. Tier A: nullify PII fields, write tombstone

If step 1 succeeds but step 2 fails, retry step 2; revocations are committed.
If step 1 fails (Tier B unconfirmed), do NOT proceed to step 2. Account stays active until retry.

### B-5: Cross-region revocation log MANDATORY

```yaml
multi_region:
  primary_region: us-east-1
  validation_regions: [us-east-1, us-west-2, eu-west-1]
  revocation_log:
    cross_region_replication: synchronous_quorum  # MANDATORY
    quorum_regions: 2  # primary + 1 secondary required for revoke ack
    on_quorum_unavailable: fail_closed  # revoke returns 503
```

Revocation log replication via PostgreSQL synchronous_standby_names with at least one cross-region standby. Validation in any secondary region:

```ts
async function validateInSecondaryRegion(keyId: string) {
  // 1. Check local revocation log (cross-region replicated)
  const localLog = await db.queryOne(
    `SELECT MAX(ts) AS latest FROM agent_revocation_log WHERE region != $1`,
    [currentRegion]
  )
  // 2. Compare to last known global epoch
  const globalEpoch = await redis.get('agent-auth:global-revocation-epoch')
  const localEpoch = await redis.get(`agent-auth:local-revocation-epoch:${currentRegion}`)
  if (globalEpoch !== localEpoch) {
    // Local out of sync, route to primary OR fail closed
    if (config.on_local_out_of_sync === 'fail_closed') return reject(503, 'region_stale')
    if (config.on_local_out_of_sync === 'route_to_primary') return await primaryValidate(keyId)
  }
  // 3. Standard validation
  return standardValidate(keyId)
}
```

If lib is single-region: this section ignored; revocation log lives in primary only.

### B-6: Recovery approval callback signed + nonce + replay-safe

```
Lib → SaaS approval webhook:
  POST /your-approval-handler
  Headers:
    X-Agent-Auth-Signature: HMAC-SHA256(body, recovery_webhook_secret)
    X-Agent-Auth-Request-Id: <uuid>
    X-Agent-Auth-Timestamp: <unix>
    X-Agent-Auth-Nonce: <random_256bit_b64>
    X-Agent-Auth-Sender-Id: agent-auth/v9
  Body: {
    "request_id": "...",
    "account_id": "...",
    "identity_subject": "github:12345",
    "approval_callback_url": "https://saas-app.../api/agent-auth/recover-account-confirm/<token>",
    "expires_at": "2026-04-30T12:00:00Z"  // 24h
  }

SaaS implements approval handler. After verification (HMAC + nonce-not-seen + timestamp-recent),
calls back:
  POST <approval_callback_url>
  Headers:
    Authorization: Bearer <recovery_webhook_token>  // SaaS-side secret
  Body: { "approve": true | false, "reason": "..." }

Lib's confirm endpoint:
  - Verifies the URL token (single-use, expires 24h)
  - Checks idempotency: if already approved/denied, return 409
  - On approve: completes recovery (issues key, encrypts to client_pubkey)
  - On deny: marks recovery session 'denied', clears state
```

```sql
CREATE TABLE agent_recovery_approvals (
  request_id UUID PRIMARY KEY,
  account_id UUID NOT NULL REFERENCES agent_accounts(id),
  poll_token TEXT NOT NULL UNIQUE,
  approval_url_token TEXT NOT NULL UNIQUE,
  webhook_nonce BYTEA NOT NULL,
  webhook_sent_at TIMESTAMPTZ NOT NULL,
  decision TEXT CHECK (decision IN ('pending','approved','denied')),
  decision_at TIMESTAMPTZ,
  decision_reason TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Replay protection:
- `webhook_nonce` checked unique on each outbound (prevents lib-side replay if SaaS endpoint replays)
- `approval_url_token` single-use via UPDATE...WHERE decision IS NULL atomic
- `Idempotency-Key` header on confirm endpoint dedup
- 24h `expires_at`, after which session locked, requires fresh /begin-registration

### B-7: External immutable audit (WORM)

```yaml
audit:
  internal:                       # in-database hash chain
    enabled: true
    table: agent_audit_log
  external:                       # WORM storage, separate trust domain
    enabled: true
    backend: s3_object_lock        # or 'gcs_bucket_lock', 'azure_immutable'
    bucket: my-audit-worm-bucket
    region: us-east-1
    retention_years: 7
    write_cadence: realtime         # or 'batch_5min'
    encryption: kms_managed
```

```ts
// Append-only writer to S3 with Object Lock
async function externalAuditWrite(event: AuditEvent) {
  const key = `audit/${dateShard(event.ts)}/${event.id}.json`
  await s3.putObject({
    Bucket: config.audit.external.bucket,
    Key: key,
    Body: JSON.stringify(event),
    ServerSideEncryption: 'aws:kms',
    SSEKMSKeyId: config.audit.external.kms_key,
    ObjectLockMode: 'COMPLIANCE',
    ObjectLockRetainUntilDate: addYears(new Date(), 7)
  })
}
```

Even if Postgres + admin DB credentials are compromised, attacker cannot rewrite history without breaking S3 Object Lock COMPLIANCE mode (which requires AWS root account with MFA delete + retention period elapsed).

Quarterly: separate auditor reads S3 audit trail, compares hash chain to in-DB log, reports tamper evidence.

### B-8: Performance rebaseline + HMAC instead of Argon2id

Cache-miss path uses HMAC-SHA256 with KMS-held pepper (not Argon2id):

```ts
// Key validation:
1. Parse Authorization header
2. Cache lookup by key_id (Redis): if hit, use cached + epoch check
3. If miss: SELECT FROM agent_api_keys WHERE key_id = ?
4. Verify: constant-time-compare(stored_hmac, hmac_sha256(secret, kms_pepper))
5. KMS pepper is loaded at boot, rotated quarterly (dual-pepper period during rotation)
```

Storage:
```sql
ALTER TABLE agent_api_keys
  RENAME COLUMN key_hash TO key_hmac;
ALTER TABLE agent_api_keys
  ADD COLUMN key_pepper_version INT NOT NULL DEFAULT 1;
```

Why HMAC > Argon2id for this case: API keys are 256-bit random, not user-chosen passwords. Argon2id provides slow-hash protection against weak passwords; for 256-bit random secrets, HMAC + KMS pepper provides equivalent security against database compromise (attacker needs both DB AND KMS pepper).

Rebaselined performance (cache-miss with HMAC):
```
Same-AZ:    P50 5-10ms,   P99 20-40ms
Cross-AZ:   P50 15-30ms,  P99 50-100ms
Cold start: P50 100-200ms (Postgres connection pool warm-up)

Worker pool: max 32 concurrent HMAC verifications
Singleflight: dedup concurrent validations of same key_id within 50ms
Cache warm: on lib startup, pre-load top 10K active keys
Storm admission control: if validation latency P99 > 200ms for 30s, return 503 to NEW
  validations (existing in-flight complete); preserves capacity for already-authenticated users
```

### B-9: GDPR clarifications

```yaml
gdpr:
  legal_basis_documents:
    - LIA: docs/gdpr/legitimate_interest_assessment.md
    - DPIA: docs/gdpr/data_protection_impact_assessment.md
    - ROPA: docs/gdpr/record_of_processing_activities.md
  pseudonymization:
    method: hmac_sha256
    pepper_storage: kms
    pepper_rotation_years: 1
    statement: |
      Pseudonymized data remains personal data per GDPR Article 4(5).
      Pseudonymization is a security measure, not erasure.
      True erasure occurs when:
        - Pseudonymization key destroyed AND
        - Source data nullified AND
        - Backups containing source data either purged or tombstoned
  retention:
    audit_log_active: 365_days
    audit_log_archived_pseudonymized: 7_years (regulatory)
    audit_log_after_erasure: 90_days_pseudonymized then full purge
  backup_restore:
    on_erasure: tombstone + post-restore reapply procedure
    procedure_doc: docs/gdpr/backup_erasure_procedure.md
    quarterly_test: required
```

Plus: vendor lib publishes annual transparency report on data subject requests handled.

---

## Other v8 round-8 items closed

### Threat model: 17→25 scenarios

Add (RT-19 through RT-25):
- RT-19: Forged /recover-account-confirm callback → HMAC + nonce + replay protection (see B-6)
- RT-20: Client public-key substitution during sealed-box delivery → client_pubkey bound to poll_token at /begin-registration; cannot be changed mid-flow
- RT-21: Session fixation around recovery/poll → poll_token entropy 256-bit; immutable once issued
- RT-22: KMS/HSM signing key compromise → key isolated in HSM; rotation procedure documented; lib fails closed if KMS unreachable
- RT-23: Backup restore resurrecting revoked state → tombstone application during restore; integration test
- RT-24: GitHub account takeover / SAML deprovisioning → relies on GitHub's own controls; lib responds to webhooks; SaaS owner can manually revoke
- RT-25: Redis partition during validation → if Redis quorum lost, lib falls through to Postgres directly (degraded but correct)

Fix RT-1 through RT-25 count.

### Supply chain hardening additions

```yaml
supply_chain:
  github_actions:
    pin_by_sha: true              # actions/checkout@SHA, not @v4
    require_phishing_resistant_mfa: true  # passkey or hardware key
  npm_publishing:
    method: trusted_publishing_oidc  # GitHub Actions OIDC → npm
    legacy_token_publishing: disabled  # no NPM_TOKEN after migration
    provenance: enabled
    provenance_limitations_doc: docs/supply_chain/provenance_limits.md  # private repo limits stated
  builds:
    lockfile: package-lock.json (committed)
    install_cmd: npm ci             # not npm install
    reproducible_target: SLSA L3
  consumer_verification:
    instructions: |
      # In CI:
      npm install --foreground-scripts=false
      npm audit signatures
      # Or: cosign verify-blob-attestation --bundle agent-auth.tgz.sigstore agent-auth.tgz
  scorecard_minimum: 8.5
  release_approval:
    git_tags_protected: true
    require_two_reviewers: true
    require_environment_approval: production  # GitHub Environments
  secret_scanning: github_native + gitleaks
  dependency_review: github_dependency_review_action
```

### Admin CLI hardening

```yaml
admin_cli:
  destructive_ops_require:
    auth_method: webauthn  # FIDO2 hardware key REQUIRED, no fallback
    two_person_rule: true
    jit_rbac: true  # role granted for 1h, audit logged
  non_destructive_ops:
    auth_method: webauthn | totp_with_hardware_key
  device_posture:
    require_managed_device: true  # MDM-attested
  external_audit: required (separate trust domain, B-7)
  break_glass:
    procedure: docs/break_glass.md
    requires_co_signer: true
    incident_post_mortem: required within 24h
```

### SOC 2 expansions

CC6.1 additions:
- Quarterly access reviews
- JIT/break-glass for admin
- Documented offboarding procedure for admin role removal

CC8.1 additions:
- Migration logs in audit DB
- Approval records for schema changes
- Test results for forward-compatibility validation
- Rollback evidence per migration

CC9.2 expansions:
- Vendor inventory: GitHub, Anthropic (future), AWS, Postgres provider, Redis provider
- DPAs/security reviews for each vendor
- Annual review cadence
- Subprocessor list maintained

---

## Round-9 audit questions

1. Are all 9 round-8 blockers now correctly closed in invariants and code-level detail?

2. The mandatory revocation_epoch check adds 1 Redis GET per validation. Is this acceptable performance overhead for paying customer SLA, or should there be an opt-out for non-critical SaaS?

3. Tier B commit timeout 5s + return 503 + idempotency — does this give consumers a clean retry semantics, or are there edge cases (e.g. timeout on success vs failure indistinguishable)?

4. WORM external audit via S3 Object Lock COMPLIANCE mode: any way to compromise this without AWS root account access?

5. Recovery approval callback design: 3 secrets in play (webhook_secret HMAC, approval_url_token, Idempotency-Key). Any redundancy or gaps?

6. HMAC-SHA256 with KMS pepper instead of Argon2id: defensible to security review? Compared against industry practice (Stripe, GitHub, etc. use ?)

7. 25 threat scenarios. Now complete? Any still missing?

8. GDPR clause stating pseudonymized data remains personal data — does this satisfy DPO review?

9. Final grade. Production-ready paying-customer? CISO would sign off?

10. If still gaps: what EXACTLY blocks A+ grade?
