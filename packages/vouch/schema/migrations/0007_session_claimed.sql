-- 0007_session_claimed.sql
-- Adds 'claimed' to session_status_enum so registration-status can mark
-- the session single-use after the encrypted_payload is read.
--
-- Why: a stolen poll_token can't decrypt the sealed-box payload (it's
-- bound to client_pubkey), but exposing the ciphertext on every poll
-- expands the attacker's window for cryptanalysis or future-day-attacks.
-- The 'claimed' transition makes the payload genuinely one-shot.
--
-- New transition graph:
--   pending -> exchanging -> ready -> claimed -> (terminal)
--                          \-> failed
--                          \-> expired
--
-- Defense in depth: when status=claimed, result_ciphertext MUST be
-- NULL (the row keeps account_id + audit metadata, but the payload
-- itself is gone).

BEGIN;

ALTER DOMAIN session_status_enum DROP CONSTRAINT session_status_enum_check;
ALTER DOMAIN session_status_enum ADD CHECK (VALUE IN (
  'pending', 'exchanging', 'ready', 'claimed', 'failed', 'expired'
));

-- Enforce: claimed rows must have null ciphertext.
ALTER TABLE agent_registration_sessions
  ADD CONSTRAINT chk_session_claimed_no_ciphertext
  CHECK (status <> 'claimed' OR result_ciphertext IS NULL);

COMMIT;
