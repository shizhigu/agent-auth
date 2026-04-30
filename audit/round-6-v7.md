# agent-auth v7 spec — production-ready paying-customer target

**Target**: production-ready, paying customers comfortable depositing real workloads. NOT internal beta. Codex round-6 was A-; v7 must hit A or higher with all "must-fix-before-production" items closed AND new production-grade operational/threat/compliance content.

This is a focused patch over v3+v4+v5+v6. Reference earlier specs for unchanged content.

## v7 changes summary

### Codex round-6 required clarifications (A- → A)
| # | Item | v7 fix |
|---|---|---|
| 1 | Fail-closed unknown identity states / revocation_source | All status enums use exhaustive switch with default → reject. CHECK constraints on enum columns. |
| 2 | Account binding check in recovery (5th case) | Recovery rejects if account.status != 'active'. Recovery session bound to account_id. |
| 3 | Webhook replay cursor + alert | Persisted `last_seen_delivery_id` cursor. Configurable lookback. Alert when catch-up cap hit. |
| 4 | Sealed-box retry semantics | Bounded 3 retries with same key. Erase on success/timeout/cancel/3rd failure. |
| 5 | Redis SET as acceleration only; Postgres authority | Reconciliation job rebuilds Redis SET from Postgres hourly. SCARD monitored. |

### Production-grade additions (new in v7)
| Area | Addition |
|---|---|
| Audit tokenizer | Split on URL/JSON/header delimiters: `?`, `&`, `=`, `/`, `#`, `.`, `:` |
| Emergency rotation | Predecessor `revoked_at + rotation_state='revoked'` set in same tx as successor INSERT |
| Operational runbook | Documented procedures for: cache flush, force-revoke, missed-webhook recovery, identity unblock, key extraction for incident response |
| Observability | Required metrics, log fields, trace spans, SLO targets |
| Performance budget | P50/P99 latency targets per endpoint; benchmark suite in lib |
| Disaster recovery | Backup strategy for accounts/identities/keys; PITR for Postgres; Redis as cache only |
| Multi-region | Active-passive design; read-replica permissible for lookups; writes single-region |
| Threat model | 8 named red-team scenarios with tested mitigations |
| Compliance | SOC 2 control mapping; GDPR right-to-erasure; data residency |
| Library supply chain | Sigstore signing; SBOM; pinned deps; npm provenance |
| API versioning | URL versioning `/v1/`; deprecation policy |
| Schema migrations | Forward-compatible migrations; never destructive online |

---

## Production clarifications (codex round-6 must-fixes)

### #1: Fail-closed enum handling

```ts
type IdentityStatus = 'active' | 'revoked' | 'expired'
type RevocationSource = 'webhook' | 'expiry' | 'manual' | 'cascade' | 'admin'

function canReactivateIdentity(s: IdentityStatus, src: RevocationSource | null): boolean {
  if (s === 'active') return true
  if (s === 'revoked') {
    switch (src) {
      case 'webhook': return true
      case 'expiry':  return true
      case 'manual':  return false
      case 'cascade': return false
      case 'admin':   return false
      case null:      return false   // unknown source → fail closed
      default:        return false   // future enum values not yet supported → fail closed
    }
  }
  if (s === 'expired') return true   // can refresh
  return false                        // unknown status → fail closed
}
```

```sql
ALTER TABLE agent_identities
  ADD CONSTRAINT identities_revocation_source_known CHECK (
    revocation_source IS NULL OR
    revocation_source IN ('webhook','expiry','manual','cascade','admin')
  );
```

Application code MUST handle the `default` case as reject. Lint rule (eslint custom):
forbid `switch` on these enums without `default` clause.

### #2: Recovery account binding

```sql
-- agent_registration_sessions extension for recovery
ALTER TABLE agent_registration_sessions
  ADD COLUMN target_account_id UUID REFERENCES agent_accounts(id);
-- For 'recover' kind: must reference the account being recovered
-- For 'register'/'add_key': NULL
ALTER TABLE agent_registration_sessions ADD CONSTRAINT recovery_target_required CHECK (
  (kind != 'recover') OR (target_account_id IS NOT NULL)
);
```

Recovery flow updated:
```
1. POST /begin-registration { intent: 'recover', account_id: <claimed> }
   → Verify account exists, status='active' or 'suspended' (NOT closed)
   → Generate poll_token, kind='recover', target_account_id=<account_id>
2. Fresh OAuth completes
3. /callback verifies attestation, finds matching identity
4. Validate:
   a. identity.account_id == session.target_account_id → ok
   b. else → REJECT 403 'identity_account_mismatch'
   c. account.status == 'active' or 'suspended' → ok
   d. account.status == 'closed' → REJECT 410 'account_closed'
   e. canReactivateIdentity(identity.status, identity.revocation_source) → ok or reject
5. Reactivate identity (or block per rules)
6. Issue new key
7. Owner approval webhook (if configured) called BEFORE issuing key
```

### #3: Webhook replay cursor + alerts

```sql
CREATE TABLE agent_webhook_replay_state (
  provider                TEXT PRIMARY KEY,
  last_seen_delivery_id   TEXT,
  last_run_at             TIMESTAMPTZ,
  last_run_status         TEXT CHECK (last_run_status IN ('ok','partial','failed','cap_hit')),
  catch_up_pages          INT NOT NULL DEFAULT 0,
  total_redelivered       BIGINT NOT NULL DEFAULT 0,
  config_max_pages        INT NOT NULL DEFAULT 10,
  config_lookback_hours   INT NOT NULL DEFAULT 24
);
```

```ts
async function reconcileWebhookDeliveries() {
  const state = await db.queryOne(
    `SELECT * FROM agent_webhook_replay_state WHERE provider='github_app' FOR UPDATE`
  )
  let pages_processed = 0
  let url: string | null =
    `https://api.github.com/app/hook/deliveries?per_page=100` +
    (state.last_seen_delivery_id ? `&cursor=${state.last_seen_delivery_id}` : '')

  let oldest_seen: string | null = null
  let total_redelivered = 0
  let cap_hit = false

  while (url && pages_processed < state.config_max_pages) {
    const resp = await fetchWithGithubAppJwt(url)
    if (!resp.ok) {
      log.warn('webhook_replay_fetch_failed', { status: resp.status, url })
      break
    }
    const deliveries = await resp.json()
    for (const d of deliveries) {
      if (oldest_seen === null) oldest_seen = d.id
      // Stop walking back further than lookback_hours
      const delivered_age_hours = (Date.now() - new Date(d.delivered_at).getTime()) / 3.6e6
      if (delivered_age_hours > state.config_lookback_hours) break

      const action = await processDelivery(d)
      if (action === 'redelivered') total_redelivered++
    }
    url = parseLinkHeaderNext(resp.headers.get('Link') ?? '')
    pages_processed++
  }

  if (pages_processed >= state.config_max_pages && url !== null) {
    cap_hit = true
    metrics.increment('agent_auth.webhook_replay.cap_hit')
    log.alert('webhook_replay_cap_hit', { provider: 'github_app', pages: pages_processed })
  }

  await db.query(
    `UPDATE agent_webhook_replay_state
       SET last_seen_delivery_id = $1,
           last_run_at = now(),
           last_run_status = $2,
           catch_up_pages = $3,
           total_redelivered = total_redelivered + $4
     WHERE provider = 'github_app'`,
    [oldest_seen, cap_hit ? 'cap_hit' : 'ok', pages_processed, total_redelivered]
  )
}
```

Operator backfill mode:
```
agent-auth backfill --provider github_app --lookback-hours 168
```

Bypasses the cursor for forced wider sweep. Used after extended outage.

### #4: Sealed-box retry semantics

Documented client SDK contract:

```ts
class AgentRegistrar {
  private agentKp: KeyPair | null = null
  private decryptAttempts = 0
  private static MAX_DECRYPT_RETRIES = 3

  async pollRegistrationStatus(pollToken: string): Promise<KeyMaterial | { pending: true }> {
    const resp = await fetch(`${baseUrl}/api/agent-auth/registration-status`, {
      method: 'POST', body: JSON.stringify({ poll_token: pollToken })
    })
    const body = await resp.json()
    if (body.status === 'pending') return { pending: true }
    if (body.status === 'failed') {
      this.cleanup()
      throw new Error(`Registration failed: ${body.code}`)
    }

    // Status 'completed': decrypt
    if (!this.agentKp) {
      throw new Error('Session ended before completion')
    }
    try {
      const decrypted = sodium.crypto_box_seal_open(
        base64url_decode(body.encrypted_payload),
        this.agentKp.publicKey,
        this.agentKp.privateKey
      )
      // Success: erase key, reset counter
      this.cleanup()
      return JSON.parse(Buffer.from(decrypted).toString('utf8'))
    } catch (err) {
      this.decryptAttempts++
      if (this.decryptAttempts >= AgentRegistrar.MAX_DECRYPT_RETRIES) {
        this.cleanup()
        throw new Error(`Decrypt failed ${AgentRegistrar.MAX_DECRYPT_RETRIES} times. Re-register.`)
      }
      // Bounded retry: ciphertext might be a transient transport corruption.
      // DO NOT regenerate keypair. The encrypted payload was sealed to the original public key.
      return { pending: true }   // signal caller to retry
    }
  }

  cleanup() {
    if (this.agentKp) {
      sodium.memzero(this.agentKp.privateKey)
      this.agentKp = null
    }
    this.decryptAttempts = 0
  }

  // Also called on session timeout (poll loop exceeded 5 min) or explicit cancel
}
```

Server-side: encrypted_payload is NOT cleared on retrieve (it's idempotent). The agent's cleanup is local-only.

### #5: Redis SET reconciliation

```ts
// Hourly reconciliation job
async function reconcileAccountKeySets() {
  // Walk all active accounts
  const accounts = await db.query(
    `SELECT id FROM agent_accounts WHERE status = 'active' AND updated_at > now() - interval '7 days'`
  )

  for (const acc of accounts.rows) {
    // Authoritative key list from Postgres
    const dbKeys = await db.query(
      `SELECT key_id FROM agent_api_keys
       WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
      [acc.id]
    )
    const dbKeySet = new Set(dbKeys.rows.map(r => r.key_id))

    // Current Redis set
    const redisKeys = await redis.smembers(`agent-auth:account-keys:${acc.id}`)
    const redisKeySet = new Set(redisKeys)

    // Add missing from DB
    const missingInRedis = [...dbKeySet].filter(k => !redisKeySet.has(k))
    if (missingInRedis.length > 0) {
      await redis.sadd(`agent-auth:account-keys:${acc.id}`, ...missingInRedis)
      metrics.increment('agent_auth.redis_reconciliation.added', missingInRedis.length)
    }

    // Remove stale from Redis
    const staleInRedis = [...redisKeySet].filter(k => !dbKeySet.has(k))
    if (staleInRedis.length > 0) {
      await redis.srem(`agent-auth:account-keys:${acc.id}`, ...staleInRedis)
      metrics.increment('agent_auth.redis_reconciliation.removed', staleInRedis.length)
    }

    // SCARD monitoring
    const card = await redis.scard(`agent-auth:account-keys:${acc.id}`)
    if (card > 1000) {
      log.warn('account_key_set_too_large', { account_id: acc.id, scard: card })
    }
  }
}
```

Postgres is authoritative. Redis SET is acceleration. Account-wide invalidation correctness does NOT depend on Redis SET being perfect — fallback is to scan Postgres.

```ts
async function invalidateAccountKeys(accountId: string) {
  // Try Redis SET first (fast path)
  let keyIds = await redis.smembers(`agent-auth:account-keys:${accountId}`)
  if (keyIds.length === 0) {
    // Fallback to Postgres (slow but correct)
    const result = await db.query(
      `SELECT key_id FROM agent_api_keys
       WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
      [accountId]
    )
    keyIds = result.rows.map(r => r.key_id)
  }
  // ... rest same as v6
}
```

---

## Production-grade additions

### Audit tokenizer (extended delimiters)

```ts
function scanForHighEntropyTokens(s: string): boolean {
  // Split on URL/JSON/header delimiters, KEEP base64url chars (_, -)
  const tokens = s.split(/[\s,;:|"'<>(){}\[\]?&=/#.]+/).filter(t => t.length >= 32)
  for (const t of tokens) {
    if (UUID_REGEX.test(t)) continue
    if (ULID_REGEX.test(t)) continue
    if (TRACE_ID_REGEX.test(t)) continue
    if (POLL_TOKEN_REGEX.test(t)) return true   // pak_/pkr_/pad_ explicitly redacted
    if (shannonBitsPerChar(t) >= 4.5) return true
  }
  return false
}

const POLL_TOKEN_REGEX = /^p(ak|kr|ad)_[A-Za-z0-9_-]{43}$/
```

### Emergency rotation transaction

```sql
-- Single transaction for grace_seconds=0 path:
BEGIN;
  -- Acquire lock on predecessor
  SELECT * FROM agent_api_keys WHERE id = $old_id AND rotation_state = 'active' FOR UPDATE;

  -- Insert successor (trigger sets predecessor.replaced_by_key_id)
  INSERT INTO agent_api_keys (..., created_by_key_id) VALUES (..., $old_id) RETURNING id INTO $new_id;

  -- Mark predecessor revoked IMMEDIATELY (not just rotated)
  UPDATE agent_api_keys
  SET rotation_state = 'revoked',
      revoked_at = now(),
      revoked_reason = 'emergency_rotation',
      rotated_at = now(),
      rotation_grace_expires_at = now()
  WHERE id = $old_id;
COMMIT;

-- After commit:
-- Cache invalidation (DEL Redis entry, PUBLISH, etc.) — best effort
```

CHECK constraint already enforces `rotation_state='revoked'` ↔ `revoked_at IS NOT NULL`. Atomic.

### Operational runbook (new section)

#### RB-1: Force-revoke a specific key
```bash
# CLI command shipped with lib
agent-auth admin revoke-key --key-id agk_aB1cD2eF --reason "compromised"
```
Steps:
1. Postgres UPDATE with reason, revoked_at, rotation_state
2. Redis DEL `agent-auth:key:<key_id>`
3. Redis SREM from `agent-auth:account-keys:<account_id>`
4. Redis PUBLISH invalidation
5. Audit log entry kind='admin_revoke'

#### RB-2: Suspend account
```bash
agent-auth admin suspend-account --account-id <uuid> --reason "abuse_investigation"
```
Cascade: all keys revoked, identities marked suspended, Redis flushed.

#### RB-3: Force missed webhook reconciliation
```bash
agent-auth backfill --provider github_app --lookback-hours 168
```

#### RB-4: Cache flush (incident response)
```bash
agent-auth admin flush-cache --confirm
```
Wipes all Redis `agent-auth:*` keys. Validations fall back to Postgres for next 30s. Use in extreme cases (cache poisoning suspected).

#### RB-5: Identity unblock (admin override after manual revocation)
```bash
agent-auth admin unblock-identity --identity-id <uuid> --reason "false_positive"
```
Sets identity status='revoked' → 'active' WITH revocation_source='admin' override. Audit logged with admin user.

#### RB-6: Key extraction for incident response
```bash
agent-auth admin export-account --account-id <uuid> --format json --include-audit
```
Exports account, identities, key metadata (hashes only, never secrets), audit log slice. For legal/compliance.

#### RB-7: Database migration
```bash
agent-auth migrate --target-version v7
agent-auth migrate --rollback
```
All migrations are forward-compatible: lib v6 must be able to read v7 schema (additive only). Destructive changes require feature flag + dual-mode period.

### Observability requirements

#### Required metrics (Prometheus exposition)
```
# Counters
agent_auth_registrations_total{provider, kind, outcome}
agent_auth_keys_issued_total{tier, identity_provider}
agent_auth_keys_rotated_total{type=planned|emergency}
agent_auth_keys_revoked_total{reason}
agent_auth_validations_total{outcome=accepted|rejected, reject_reason}
agent_auth_rate_limit_hits_total{dimension=per_key|per_account|per_route|per_ip}
agent_auth_webhook_events_total{provider, event_type, status}
agent_auth_webhook_replay_redelivered_total{provider}

# Gauges
agent_auth_keys_active
agent_auth_accounts_by_tier{tier}
agent_auth_pending_registrations
agent_auth_redis_reconciliation_drift{kind=added|removed}

# Histograms
agent_auth_validation_latency_seconds (buckets: 0.001, 0.005, 0.01, 0.05, 0.1, 0.5)
agent_auth_registration_total_duration_seconds
agent_auth_provider_call_latency_seconds{provider, operation}
```

#### Required log fields (structured)
Every log line includes: `request_id`, `agent_auth_version`, `endpoint`, `account_id` (if known), `key_id` (if known), `result`, `duration_ms`. Secrets and tokens NEVER logged (scrubbing rules apply).

#### OpenTelemetry traces
- Top-level span per public endpoint
- Child spans on identity provider calls (named `idp.<provider>.<op>`)
- Child spans on cache lookup (hit/miss attribute)
- Child spans on rate limit check
- Span events for invalidation pubsub publishes

#### SLO targets (lib commits to)
- Validation latency P50 < 5ms (cache hit), P99 < 50ms
- Registration P50 < 200ms (excluding upstream IdP latency)
- Webhook processing P50 < 100ms
- Cache hit rate > 95% in steady state
- Rate limit decisions atomic per dimension (Redis TIME)

Alerts (consumer-defined, but lib emits):
- Cache hit rate < 80% for 5 min
- Webhook replay cap_hit
- Redis reconciliation drift > 5% of accounts
- Identity reactivation rate spike (> 10x baseline)

### Performance budget + benchmark suite

Lib ships `agent-auth bench` that runs:
- 10K validations against fixed key set, P50/P99 measured
- 1K registrations with mock provider
- Rate limit at 10K QPS sustained
- Concurrent rotation (100 parallel rotates)

Benchmarks gated in CI: regressions > 20% block merge.

### Disaster recovery

#### Backup strategy
- Postgres: PITR with 7-day retention; logical backup nightly to S3
- Redis: snapshots (RDB) every 1h to S3; ephemeral state OK to lose (rate limit counters, cache)
- Config: lib config + secrets in K8s sealed-secrets / similar; encrypted at rest

#### Recovery RTO/RPO
- RTO: 1 hour from last verified backup (rebuild Postgres, recreate Redis)
- RPO: 5 minutes (Postgres WAL streaming) for accounts/identities/keys; Redis loss = 30s service degradation (cache rebuild)

#### Tested DR procedure
Quarterly DR drill: restore from cold backup to staging env, run integration suite. Document time-to-recovery.

### Multi-region

v0.1 design: active-passive.
- Primary region: writes (registration, rotation, revoke).
- Secondary region: read-only validation (read replica of Postgres + Redis cache).
- Failover: manual; promotes secondary to primary.

Replication lag: validation in secondary region may serve stale auth for up to lag duration. Document.

For sub-second failover or active-active: out of scope v0.1.

### Threat model — 8 named red-team scenarios

| # | Scenario | Mitigation |
|---|---|---|
| RT-1 | Phishing user to authorize attacker's GitHub App | Out of scope (attacker controls user). Mitigation: SaaS UX clearly identifies our app. |
| RT-2 | Steal poll_token via XSS in callback page | Callback page contains zero secrets, no JS that can leak. CSP enforces. |
| RT-3 | Compromise Redis instance | Cache only; no secrets stored. Argon2id hashes Postgres only. Worst case: 30s stale auth window during which revoked keys may pass. |
| RT-4 | Compromise Postgres replica (read-only) | Hashes not plaintext; subjects/IDs visible. PII minimized. SaaS-side IDS detects unusual queries. |
| RT-5 | npm supply-chain attack on agent-auth lib | Sigstore signing + npm provenance + SBOM. Consumers verify signatures. |
| RT-6 | Replay GitHub webhook | HMAC-SHA256 + dedup on X-GitHub-Delivery. Mismatched payload_hash on duplicate alerts. |
| RT-7 | Steal API key from agent's process memory | Outside lib's threat boundary. Mitigations: short-lived keys, scope minimization, leaked-prefix scanner. |
| RT-8 | Time-based farming (Sybil at warm tier) | Documented compromise. Warm tier MUST NOT unlock expensive ops. SaaS owner gates hot tier. |

For each scenario, integration test exercises the mitigation in CI.

### Compliance

#### SOC 2 control mapping
- CC6.1 (logical access): every auth path documented + tested
- CC6.6 (key management): Argon2id, key rotation, audit log
- CC7.1 (incident detection): alerts spec'd
- CC7.2 (incident response): runbook RB-1 through RB-7

#### GDPR
- Right to erasure: `/api/agent-auth/account/<id>` DELETE endpoint nullifies PII fields, retains audit log per legal hold
- Right to access: `/api/agent-auth/account/<id>/export` returns user's account+identities+key metadata
- Data residency: Postgres + Redis location configurable per SaaS deployment

#### Data classification
- HIGH: API key secrets (hashed, never plaintext stored or logged)
- MEDIUM: upstream subject IDs, audit log, account metadata
- LOW: tier, scopes, timestamps

### Library supply chain security

```yaml
# Release pipeline
- Sigstore cosign signs every release artifact
- npm publish --provenance (links GitHub Actions to npm package)
- Generate SBOM (CycloneDX format) bundled in package
- All deps pinned to exact versions in package.json
- All deps audited via `npm audit --audit-level high`
- Dependency updates require PR review + CI green
- No telemetry beacons by default
```

Consumers verify with:
```bash
cosign verify --certificate-identity-regexp "https://github.com/agent-auth/agent-auth" agent-auth-7.0.0.tgz
```

### API versioning

URL versioning: `/api/agent-auth/v1/...`. Lib supports concurrent v1 + v2 endpoints during 12-month deprecation window. Schema changes are additive.

Deprecation policy:
- New version announced with 12 months notice
- Old version returns `Deprecation: <date>` header
- Hard sunset only after 12 months

### Schema migration safety

Every migration is:
1. Forward-compatible (lib version N reads schema N+1 without error)
2. Reversible (each up-migration has a down-migration)
3. Online (no table locks > 1 second)
4. Tested on copy of prod-shape data

Destructive changes (drop column, change type) require:
- Feature flag gating
- Dual-mode period (read both old + new)
- Two-deploy migration (old code still running ↔ new schema)

---

## Round-7 audit questions

1. Does v7 actually hit production-ready paying-customer level, or is it still missing items a CISO/security review would catch?

2. The threat model has 8 RT scenarios. Are these the right 8? Missing critical ones?

3. SOC 2 control mapping — are the cited controls correct/sufficient for an actual audit?

4. Multi-region active-passive: is the staleness bound on secondary-region validation an acceptable production risk, or does it need active-active?

5. The performance budget (validation P50 < 5ms cache hit, P99 < 50ms) — realistic for the cache architecture as designed?

6. DR: 5-minute RPO via Postgres WAL streaming. Is this consistent with our cache + invalidation model? What happens to in-flight rotations during failover?

7. Library supply chain: Sigstore + npm provenance + SBOM. Is this the production state-of-the-art or are there additional measures (binary transparency, reproducible builds)?

8. API versioning: 12-month deprecation. Reasonable for paying customers? Too long/short?

9. GDPR right-to-erasure: nullifying PII while retaining audit log. Is "legal hold" justified retention, or do we need configurable retention per jurisdiction?

10. Final grade. Production-ready paying-customer level achieved? If not, what's the gap?
