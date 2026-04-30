-- Rollback for 0002_audit.sql. SPEC §3.17.
-- Run as agent_auth_migrator. SPEC §6.4 calls for audit data preservation
-- on rollback by default. This script drops the table family. Operators
-- who must preserve audit history should COPY rows to an archive (or
-- comment out the DROP statements below) before applying this rollback.

BEGIN;

DROP TRIGGER IF EXISTS trigger_audit_hash_chain ON agent_audit_log;
DROP FUNCTION IF EXISTS compute_audit_row_hash();

DROP TABLE IF EXISTS agent_audit_outbox;
DROP TABLE IF EXISTS agent_webhook_replay_state;
DROP TABLE IF EXISTS agent_webhook_events;

-- Default partition first, then the partitioned parent.
DROP TABLE IF EXISTS agent_audit_log_default;
DROP TABLE IF EXISTS agent_audit_log;

COMMIT;
