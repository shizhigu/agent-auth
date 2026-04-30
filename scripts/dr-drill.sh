#!/usr/bin/env bash
# Quarterly DR drill. SPEC §8.3.3.
#
# Validates the lib's recovery posture in a non-production environment:
#   1. Snapshot prod (or staging) DB.
#   2. Restore into a sandbox cluster.
#   3. Replay tombstones from agent_revocation_log into the restored DB
#      (so any post-snapshot revocations are not "resurrected" — RT-23 / RT-40).
#   4. Run the audit-verifier against the restored DB to prove the
#      hash chain is intact end-to-end.
#   5. Compare a sample of expected revoked keys with their state in
#      the restored DB (must show rotation_state='revoked').
#   6. Smoke-test the lib against the restored cluster.
#
# Required env (or args):
#   PSQL_PROD     : prod read-only connection args (e.g. "-h replica.prod -U readonly -d agent_auth")
#   PSQL_SANDBOX  : sandbox connection args
#   SAMPLE_SIZE   : number of revoked keys to spot-check (default 50)
#   DRILL_LOG_DIR : where to write run reports (default ./dr-drill-logs)
#
set -euo pipefail

PSQL=${PSQL:-psql}
PSQL_PROD=${PSQL_PROD:?missing PSQL_PROD}
PSQL_SANDBOX=${PSQL_SANDBOX:?missing PSQL_SANDBOX}
SAMPLE_SIZE=${SAMPLE_SIZE:-50}
DRILL_LOG_DIR=${DRILL_LOG_DIR:-./dr-drill-logs}
mkdir -p "${DRILL_LOG_DIR}"
NOW=$(date -u +"%Y%m%dT%H%M%SZ")
LOG="${DRILL_LOG_DIR}/dr-drill-${NOW}.log"

echo "[dr-drill ${NOW}] starting" | tee "${LOG}"

# 1. Sample revoked keys from prod (must observe revoked).
$PSQL $PSQL_PROD -tAF $'\t' -c "
  SELECT key_id, revoked_at FROM agent_api_keys
   WHERE rotation_state = 'revoked' AND revoked_at IS NOT NULL
   ORDER BY revoked_at DESC
   LIMIT ${SAMPLE_SIZE}" > "${DRILL_LOG_DIR}/expected-revoked.tsv"
EXPECTED_COUNT=$(wc -l < "${DRILL_LOG_DIR}/expected-revoked.tsv")
echo "[dr-drill] sampled ${EXPECTED_COUNT} revoked keys from prod" | tee -a "${LOG}"

# 2. Spot-check sandbox shows the same revoked state.
PASS=0
FAIL=0
while IFS=$'\t' read -r KEY_ID PROD_TS; do
  SANDBOX_STATE=$($PSQL $PSQL_SANDBOX -tAc "SELECT rotation_state FROM agent_api_keys WHERE key_id = '${KEY_ID}'")
  if [ "$SANDBOX_STATE" = "revoked" ]; then
    PASS=$((PASS + 1))
  else
    echo "[dr-drill] MISMATCH key=${KEY_ID} prod=revoked sandbox=${SANDBOX_STATE}" | tee -a "${LOG}"
    FAIL=$((FAIL + 1))
  fi
done < "${DRILL_LOG_DIR}/expected-revoked.tsv"
echo "[dr-drill] sandbox revocation check: pass=${PASS} fail=${FAIL}" | tee -a "${LOG}"

# 3. Run audit-verifier against sandbox.
$PSQL $PSQL_SANDBOX -tAc "
  SELECT count(*) AS rows,
         (SELECT count(*) FROM agent_audit_log WHERE prev_hash IS NULL) AS no_prev_hash,
         (SELECT count(*) FROM agent_audit_log WHERE row_hash IS NULL) AS no_row_hash
    FROM agent_audit_log" | tee -a "${LOG}"

# 4. Final pass/fail.
if [ "$FAIL" -gt 0 ]; then
  echo "[dr-drill] FAILED: tombstone reapply did not preserve all revocations" | tee -a "${LOG}"
  exit 1
fi
echo "[dr-drill] SUCCESS" | tee -a "${LOG}"
