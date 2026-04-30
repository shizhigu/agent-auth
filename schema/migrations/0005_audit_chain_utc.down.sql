-- Rollback for 0005_audit_chain_utc.sql.
-- Reverts the trigger function to the session-TZ form of 0002. Note: this
-- is NOT safe for any deployment running with TIMEZONE != UTC — the chain
-- will misalign with daily partitions and the §6.4.1 verifier. Only roll
-- back if you are pinning Postgres TIMEZONE = 'UTC' globally.
--
-- Run as agent_auth_migrator.

BEGIN;

CREATE OR REPLACE FUNCTION compute_audit_row_hash() RETURNS TRIGGER AS $$
DECLARE
  prev BYTEA;
  canonical TEXT;
BEGIN
  SELECT row_hash INTO prev FROM agent_audit_log
    WHERE ts >= date_trunc('day', NEW.ts)
    ORDER BY id DESC LIMIT 1;
  IF prev IS NULL THEN
    prev = decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
  END IF;

  NEW.prev_hash = prev;

  canonical = jsonb_build_object(
    'id', NEW.id,
    'ts', NEW.ts,
    'event_type', NEW.event_type,
    'account_id', NEW.account_id,
    'key_id', NEW.key_id,
    'endpoint', NEW.endpoint,
    'status_class', NEW.status_class,
    'meta_hash', encode(digest(COALESCE(NEW.meta::text, ''), 'sha256'), 'hex')
  )::text;

  NEW.row_hash = digest(prev || canonical::bytea, 'sha256');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
