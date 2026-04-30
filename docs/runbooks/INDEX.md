# Runbooks

Operational procedures for agent-auth. Each runbook is referenced by alert conditions in SPEC.md Part VII §7.5.

| ID | Title | Trigger | Severity |
|---|---|---|---|
| RB-1 | Force-revoke a specific key | Customer reports compromised key OR leaked-prefix scanner finding | P1 |
| RB-2 | Suspend account (cascade) | Abuse investigation OR validation_availability_breach | P1 |
| RB-3 | Tier B unknown outcome resolution | tier_b_unknown_outcome alert | P1 |
| RB-4 | Cache flush (incident response) | Cache poisoning suspected OR cache_hit_rate_drop | P2 |
| RB-5 | Identity unblock (admin override) | False positive on manual revocation | P3 |
| RB-6 | Audit log tamper response | audit_hash_chain_break OR audit_worm_write_failed | P0 |
| RB-7 | Redis reconciliation drift | redis_reconciliation_drift alert | P3 |
| RB-8 | Post-failover barrier reset | Postgres primary failover OR timeline_mismatch alert | P0 |
| RB-9 | Webhook missed-delivery backfill | webhook_replay_cap_hit OR extended outage | P2 |

Full procedures are in `SPEC.md Part VIII §8.2`. This index is for quick lookup during incidents.

## Severity definitions

- **P0**: critical service impact OR security incident; page on-call immediately
- **P1**: degraded service for paying customers; respond within 15 minutes
- **P2**: degraded service or pending failure; respond within 1 hour
- **P3**: operational concern, no immediate impact; respond within 1 business day

## Communication during incidents

```
SEV-0 / SEV-1:
  - Internal: Slack #agent-auth-oncall + page CISO if security
  - Customer: status page update within 15 min
  - Post-incident: blameless post-mortem within 7 days

SEV-2:
  - Internal: Slack #agent-auth-ops
  - Customer: status page if customer-visible

SEV-3:
  - Internal: Jira ticket
```

## Runbook discipline

- Always log every action with timestamps in incident ticket
- Two-person rule for destructive ops (close-account, flush-cache, force-revoke-all)
- Update runbook itself if procedure was inadequate
- Quarterly tabletop exercise to validate runbooks
