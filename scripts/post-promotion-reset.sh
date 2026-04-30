#!/usr/bin/env bash
# Post-promotion reset. SPEC §4.4.4 / RB-8.
#
# Run on a freshly-promoted Postgres primary AFTER the cluster has settled
# on the new timeline. Captures the current WAL position + timeline,
# advances the global revocation barrier, flushes Redis, emits an audit
# event, and writes a readiness file the K8s probe watches.
#
# Required env (or args):
#   PSQL          : psql binary path (default: 'psql')
#   PSQL_ARGS     : connection args (e.g. "-h primary.local -U agent_auth_admin -d agent_auth")
#   REDIS_CLI     : redis-cli binary path (default: 'redis-cli')
#   REDIS_ARGS    : connection args (e.g. "-h redis.local -p 6379")
#   READINESS_FILE: file to touch on success (default: /var/lib/agent-auth/ready)
#
# Exit codes:
#   0 - success
#   1 - command failed; readiness file NOT created
#
set -euo pipefail

PSQL=${PSQL:-psql}
PSQL_ARGS=${PSQL_ARGS:-}
REDIS_CLI=${REDIS_CLI:-redis-cli}
REDIS_ARGS=${REDIS_ARGS:-}
READINESS_FILE=${READINESS_FILE:-/var/lib/agent-auth/ready}

# Capture fresh barrier on new primary.
NEW_LSN=$($PSQL $PSQL_ARGS -tAc "SELECT pg_current_wal_insert_lsn()")
NEW_TIMELINE=$($PSQL $PSQL_ARGS -tAc "SELECT timeline_id FROM pg_control_checkpoint()")

echo "[post-promotion-reset] new_lsn=${NEW_LSN} new_timeline=${NEW_TIMELINE}"

$PSQL $PSQL_ARGS <<SQL
UPDATE agent_revocation_barrier
SET last_lsn = '${NEW_LSN}'::pg_lsn,
    timeline_id = ${NEW_TIMELINE},
    updated_at = now();
INSERT INTO agent_audit_log (ts, event_type, meta, status_class)
VALUES (now(), 'promotion_completed',
        jsonb_build_object('new_timeline', ${NEW_TIMELINE},
                           'new_barrier_lsn', '${NEW_LSN}'),
        2);
SQL

# Flush Redis caches so stale entries from before the failover are gone.
# Validation immediately re-reads from the new primary.
$REDIS_CLI $REDIS_ARGS FLUSHDB

# Signal app readiness.
mkdir -p "$(dirname "${READINESS_FILE}")"
touch "${READINESS_FILE}"
echo "[post-promotion-reset] ready"
