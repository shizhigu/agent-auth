-- Rollback for 0004_idempotency.sql. SPEC §3.17.

BEGIN;

DROP TRIGGER IF EXISTS trigger_idempotency_terminal_immutable ON agent_idempotency;
DROP TRIGGER IF EXISTS trigger_idempotency_transitions ON agent_idempotency;

DROP FUNCTION IF EXISTS enforce_terminal_row_immutable();
DROP FUNCTION IF EXISTS enforce_idempotency_transitions();

DROP TABLE IF EXISTS agent_idempotency;

COMMIT;
