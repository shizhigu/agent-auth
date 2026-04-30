# agent-auth v13 — final patch (1 MUST-FIX to A)

Round-12: A- with 1 MUST-FIX. Codex states v13 = A / production-ready at design level.

## The 1 MUST-FIX

### Authoritative barrier source separate from replica

**Problem (round-12)**: Validation reads `agent_revocation_barrier` from local replica. If replica is stale, it reads old barrier, passes comparison, misses revoke.

**Fix**: barrier must come from authoritative source NOT the replica being validated.

Three options, pick by deployment:

#### Option A: Primary DB read (simple, reliable)

```ts
async function validateInSecondaryRegion(keyId: string) {
  // 1. Fetch authoritative barrier from PRIMARY (small read, infrequent)
  const authoritativeBarrier = await primaryDb.queryOne(
    `SELECT last_lsn, timeline_id FROM agent_revocation_barrier WHERE id = 1`
  )
  // Cache 1s in local memory to avoid hammering primary

  // 2. Local replica role check
  const inRecovery = await localDb.queryOne(`SELECT pg_is_in_recovery() AS ir`)
  if (!inRecovery.ir) {
    // We are primary. Direct read trusted.
    return await runStandardValidation(keyId)
  }

  // 3. Local replay position
  const replayPos = await localDb.queryOne(`SELECT pg_last_wal_replay_lsn() AS lsn`)

  // 4. Timeline match
  const localTimeline = (await localDb.queryOne(
    `SELECT timeline_id FROM pg_control_checkpoint()`
  )).timeline_id
  if (localTimeline !== authoritativeBarrier.timeline_id) {
    log.alert('lsn_timeline_mismatch')
    return reject(503, 'failover_in_progress')
  }

  // 5. Correctness gate
  if (pg_lsn_compare(replayPos.lsn, authoritativeBarrier.last_lsn) < 0) {
    if (config.on_lag === 'fail_closed') return reject(503, 'region_replication_stale')
    return await primaryValidate(keyId)  // route to primary
  }

  // 6. Local read trusted
  return await runStandardValidation(keyId)
}
```

Cost: 1 cross-region read of barrier per validation (mitigated by 1s local cache + primary read replicas).

#### Option B: Pushed barrier via control plane

```yaml
control_plane:
  barrier_propagation:
    method: redis_pubsub | nats | webhook
    primary_publishes_to: agent-auth:barrier-updates
    secondary_subscribes: true
    fallback_poll_seconds: 5      # if no push received, poll primary
```

Primary publishes barrier on every Tier B commit. Secondaries subscribe, maintain local copy. Authority: latest received message timestamp + primary signature.

```ts
async function getAuthoritativeBarrier(): Promise<{ last_lsn: string, timeline_id: number, received_at: Date }> {
  // Cached locally from pubsub stream
  const cached = barrierCache.latest
  if (cached && Date.now() - cached.received_at < 5000) return cached

  // Cache stale: poll primary directly
  return await primaryDb.queryOne(`SELECT last_lsn, timeline_id FROM agent_revocation_barrier WHERE id = 1`)
}
```

#### Option C: Signed barrier from KMS-signed control plane

For high-trust deployments: barrier signed with KMS key, distributed via CDN or DNS TXT records. Verifiable offline. Higher complexity, lower ops cost. Out of v0.1 scope; documented as future work.

**Default: Option A** for v0.1 (simplest, reliable). Option B available for low-latency requirements.

### Role detection: pg_is_in_recovery()

Replace all `pg_last_wal_replay_lsn() IS NULL` checks with `pg_is_in_recovery()`:

```ts
async function getRole(): Promise<'primary' | 'secondary'> {
  const r = await localDb.queryOne(`SELECT pg_is_in_recovery() AS ir`)
  return r.ir ? 'secondary' : 'primary'
}
```

`pg_is_in_recovery()` returns:
- `true`: node is in recovery (i.e. is a standby/secondary)
- `false`: node is primary (writable)

This is the documented, reliable signal per PostgreSQL docs.

### Idempotency trigger: explicit transition matrix

Tighten trigger to enforce full state graph:

```sql
CREATE FUNCTION enforce_idempotency_transitions() RETURNS TRIGGER AS $$
DECLARE
  allowed BOOLEAN := false;
BEGIN
  IF OLD.state = NEW.state THEN
    -- Same state allowed for retries / observer-no-change
    RETURN NEW;
  END IF;

  -- Allowed transitions:
  IF OLD.state = 'pending' THEN
    allowed := NEW.state IN ('completed', 'failed', 'unknown');
  ELSIF OLD.state = 'unknown' THEN
    allowed := NEW.state IN ('completed', 'failed', 'manual_required');
  ELSIF OLD.state = 'completed' THEN
    allowed := false;  -- terminal
  ELSIF OLD.state = 'failed' THEN
    allowed := false;  -- terminal
  ELSIF OLD.state = 'manual_required' THEN
    allowed := false;  -- terminal until admin
  END IF;

  -- Admin override: only via explicit DB role
  IF NOT allowed AND current_user = 'agent_auth_admin' THEN
    -- Audit the override
    INSERT INTO agent_audit_log (ts, event_type, meta)
    VALUES (now(), 'idempotency_admin_override',
            jsonb_build_object('key', NEW.key, 'from', OLD.state, 'to', NEW.state));
    allowed := true;
  END IF;

  IF NOT allowed THEN
    RAISE EXCEPTION 'idempotency_invalid_transition: % → %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_idempotency_transitions
BEFORE UPDATE OF state ON agent_idempotency
FOR EACH ROW EXECUTE FUNCTION enforce_idempotency_transitions();
```

This enforces the EXPLICIT transition matrix:
- pending → completed | failed | unknown
- unknown → completed | failed | manual_required
- All terminal states are sticky except admin override

`agent_auth_admin` is a separate DB role:

```sql
CREATE ROLE agent_auth_admin NOLOGIN;
GRANT USAGE ON SCHEMA public TO agent_auth_admin;
GRANT INSERT, UPDATE, DELETE ON agent_idempotency, agent_audit_log TO agent_auth_admin;
-- App role does NOT have agent_auth_admin
GRANT agent_auth_app_role TO authenticator;  -- pooled connections use app role only
-- Admin operations require SET ROLE agent_auth_admin in a separate non-pooled connection
```

Admin operations (rare, manual reconciliation) connect with admin role explicitly. No pooling. Always audit-logged via the trigger itself.

### Failover automation hook

Operator runbook RB-8 (reset barrier post-promotion) is now wired into automation:

```yaml
failover:
  promotion_hooks:
    pre_promotion: 
      - script: scripts/agent-auth/pre-promotion-checks.sh
      - blocks_promotion_on_fail: true
    post_promotion:
      - script: scripts/agent-auth/post-promotion-reset.sh
      - includes:
          - reset_revocation_barrier
          - update_timeline_id
          - flush_redis_caches
          - emit_promotion_event_to_audit
```

The post-promotion script captures `pg_current_wal_insert_lsn()` on the new primary, updates `agent_revocation_barrier.last_lsn` and `timeline_id`, flushes Redis, and emits a promotion event. Service resumes after script success.

If your DB is on AWS RDS / GCP Cloud SQL: hooks run via the database-managed failover lifecycle event (e.g. RDS event subscription → SNS → Lambda → script).

---

## Round-13 audit questions (final)

1. Is the authoritative barrier source (Option A: primary read) sufficient for correctness? Are there race conditions between barrier read and local replay position?

2. The 1s local cache on barrier reads: is 1s acceptable freshness window for paying customers, or does this re-introduce the original problem?

3. Idempotency transition matrix: comment now matches code. Any transition I'm still missing?

4. Failover promotion hooks: does this give operational guarantee, or is it still best-effort?

5. Final grade. A spec = production-ready paying-customer design level. Achieved?

6. After 13 rounds: are we at the spec ceiling? Should iteration stop?
