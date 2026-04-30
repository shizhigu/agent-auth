-- agent-auth schema — defer recovery key issuance until owner approval
-- SPEC §2.9 step 5–6.
--
-- Without this column, /callback for kind='recover' issues the new key
-- immediately, ignoring the agent_recovery_approvals row. With it,
-- /callback verifies OAuth, persists the identity reference, and
-- leaves the session in 'exchanging' until /recover-account-confirm
-- flips the approval to 'approved' (and then finalizes by issuing the
-- key on the deferred identity).
--
-- Run as agent_auth_migrator. Idempotent.

BEGIN;

ALTER TABLE agent_registration_sessions
  ADD COLUMN IF NOT EXISTS awaiting_identity_id UUID
  REFERENCES agent_identities(id);

COMMENT ON COLUMN agent_registration_sessions.awaiting_identity_id IS
  'For owner-approval-gated recovery: the OAuth-verified identity row '
  'whose key issuance is deferred until /recover-account-confirm flips '
  'the approval to approved. NULL outside this window.';

COMMIT;
