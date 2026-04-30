-- Rollback for 0006_recover_pending_approval.sql.
-- Run as agent_auth_migrator.

BEGIN;

ALTER TABLE agent_registration_sessions
  DROP COLUMN IF EXISTS awaiting_identity_id;

COMMIT;
