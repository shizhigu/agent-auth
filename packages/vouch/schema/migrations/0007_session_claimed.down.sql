-- Rollback 0007: drop 'claimed' from the enum + the no-ciphertext check.
-- Any rows already in 'claimed' state would be invalid against the old
-- enum; this rollback fails-fast on those rows so the operator can
-- decide what to do (expire them, or roll forward and re-deploy).

BEGIN;

-- Verify no rows are in 'claimed' before dropping the value.
DO $$
DECLARE
  claimed_count INTEGER;
BEGIN
  SELECT count(*) INTO claimed_count
    FROM agent_registration_sessions
   WHERE status = 'claimed';
  IF claimed_count > 0 THEN
    RAISE EXCEPTION
      '0007 rollback refused: % registration sessions are in status=''claimed''. Expire them first or roll forward.',
      claimed_count;
  END IF;
END
$$;

ALTER TABLE agent_registration_sessions
  DROP CONSTRAINT IF EXISTS chk_session_claimed_no_ciphertext;

ALTER DOMAIN session_status_enum DROP CONSTRAINT session_status_enum_check;
ALTER DOMAIN session_status_enum ADD CHECK (VALUE IN (
  'pending', 'exchanging', 'ready', 'failed', 'expired'
));

COMMIT;
