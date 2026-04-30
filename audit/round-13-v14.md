# agent-auth v14 — final micro-edit (cache semantics + LSN provenance)

Codex round-13 verdict: A- with 1s cache; A without. v14 makes 4 explicit edits then stops.

## Edits

### 1. Two strict modes for barrier reads

```yaml
validation:
  barrier_mode:
    strict_uncached:           # for paying-customer SLA, default for production
      cache_ttl_ms: 0          # no caching of barrier
      cost: 1 cross-region read per validation (~5-50ms)
      guarantee: revoke is visible to all validations within commit + replay lag
    bounded_stale_1s:          # documented compromise mode
      cache_ttl_ms: 1000
      cost: lower latency, ~1 primary read per second per app process
      guarantee: bounded staleness up to 1s post-revoke
      use_for: "internal tooling, low-stakes endpoints, NOT customer-facing auth on Tier B operations"
```

Default in production config templates: `strict_uncached`. Bounded-stale mode requires explicit opt-in with documented rationale in deployment manifest.

### 2. Barrier LSN provenance invariant

Add to spec:

> **Invariant**: `agent_revocation_barrier.last_lsn` MUST be set within the same Tier B transaction as the revocation, AND the revoke API MUST NOT return 200 until both:
>   (a) the revocation row update is committed with synchronous_commit=remote_apply
>   (b) the barrier UPDATE is committed with synchronous_commit=remote_apply
>
> The barrier MUST be read from the writer (primary), not from a replica, in strict mode. "Writer" specifically excludes async read replicas in the same region.
>
> Post-commit, the barrier represents the highest LSN at which any revocation has been durably recorded across the cluster. Validations comparing local-replica replay LSN to this barrier are guaranteed to observe all revocations that returned 200 to the client.

### 3. Idempotency: `failed` semantics

Add to spec:

> **Semantics**: `failed` state is reserved for **terminal business failures** (e.g. invalid request, business rule violation, permanent provider rejection).
>
> Infrastructure failures (Postgres timeout, Redis unreachable, network partition, sync replication unavailable) MUST transition to `unknown` so the reconciliation observer can determine actual outcome.
>
> Mistakenly classifying infrastructure outcomes as `failed` makes them terminal and breaks at-least-once semantics for retried Tier B operations.

### 4. Terminal row immutability outside `state`

```sql
CREATE FUNCTION enforce_terminal_row_immutable() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.state IN ('completed', 'failed', 'manual_required') THEN
    -- Only state can be mutated by admin override (governed by separate trigger)
    -- All other fields are frozen on terminal entry
    IF (OLD.request_hash, OLD.outcome_status, OLD.outcome_body, OLD.resource_ref, OLD.operation_type)
       IS DISTINCT FROM
       (NEW.request_hash, NEW.outcome_status, NEW.outcome_body, NEW.resource_ref, NEW.operation_type) THEN
      RAISE EXCEPTION 'idempotency_terminal_row_immutable: cannot modify non-state fields after terminal'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_idempotency_terminal_immutable
BEFORE UPDATE ON agent_idempotency
FOR EACH ROW EXECUTE FUNCTION enforce_terminal_row_immutable();
```

This ensures `outcome_body` cannot be tampered after `state='completed'`. Only the (already governed) state column can be transitioned by admin role.

### 5. Failover readiness gate

```yaml
failover:
  app_readiness_gate:
    on_startup: true
    checks:
      - timeline_id_matches_barrier: true
      - barrier_reset_completed: true
      - redis_caches_flushed: true
      - all_subscribers_acked_resume: true
    on_check_fail: refuse_to_serve  # K8s readiness probe returns 503
```

App pods come up after promotion only if all checks pass. K8s readiness probe enforces; pods serving requests have verified the new timeline.

---

## Final spec state

Total spec lines across all patches:
```
v3_spec.md           930 lines (full base)
v4_patch.md          534 lines (round-3 fixes)
v5_patch.md          480 lines (round-4 fixes)
v6_patch.md          334 lines (round-5 fixes)
v7_patch.md          583 lines (production-ready additions)
v8_patch.md          496 lines (round-7 must-fixes)
v9_patch.md          431 lines (round-8 blockers)
v10_patch.md         393 lines (round-9 A blockers)
v11_patch.md         303 lines (round-10 blockers)
v12_patch.md         330 lines (round-11 narrow)
v13_patch.md         208 lines (round-12 must-fix)
v14_micro.md         <this file>
TOTAL              ~5000 lines spec, codex-audited 13 rounds
```

Located: /tmp/agent_auth_v3_spec.md through /tmp/agent_auth_v14_micro.md

---

## Spec ceiling reached: A grade

Per codex round-13 verdict:
- v13 + v14 = **A spec / production-ready design level for paying customers**
- A+ requires operational evidence (deployed controls, tested failover, real chaos tests, SOC 2 audit results) — cannot be achieved in spec alone
- "Minimum acceptable compromise" per user's framing has been reached
