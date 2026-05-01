-- Rollback for 0003_revocation.sql. SPEC §3.17.

BEGIN;

DROP TRIGGER IF EXISTS trigger_barrier_monotonic ON agent_revocation_barrier;
DROP TRIGGER IF EXISTS trigger_epoch_monotonic ON agent_revocation_epoch;

DROP FUNCTION IF EXISTS enforce_barrier_monotonic();
DROP FUNCTION IF EXISTS enforce_epoch_monotonic();

DROP TABLE IF EXISTS agent_recovery_approvals;
DROP TABLE IF EXISTS agent_revocation_barrier;
DROP TABLE IF EXISTS agent_revocation_epoch;
DROP TABLE IF EXISTS agent_revocation_log;

COMMIT;
