-- agent-auth schema — audit hash chain UTC alignment
-- SPEC §3.8 + §6.4.1. Without this fix the trigger uses session-local
-- time when computing the per-day chain seed, which misaligns with the
-- UTC-aligned partition manager (jobs/audit-partition-manager.ts) and
-- the UTC-scoped hourly verifier (jobs/audit-verifier.ts). A SaaS team
-- whose Postgres session TIMEZONE is not UTC would chain rows across
-- UTC-day boundaries and the verifier would surface a false break at
-- the start of every UTC day.
--
-- date_trunc(field, source, time_zone) is PG14+; the project requires
-- Postgres 16 per SPEC §3.1.
--
-- CREATE OR REPLACE — no data migration; existing rows retain their
-- (potentially session-TZ-influenced) hashes. Operators who need
-- byte-perfect chains across the migration boundary can re-run
-- verifyAuditChain on each historical UTC day; per SPEC §6.4.1, RB-6
-- cross-references WORM for forensic byte-level comparison.
--
-- Run as agent_auth_migrator. Idempotent.

BEGIN;

CREATE OR REPLACE FUNCTION compute_audit_row_hash() RETURNS TRIGGER AS $$
DECLARE
  prev BYTEA;
  canonical TEXT;
BEGIN
  -- Previous row in the same UTC-day window (or 0x00...00 for first row).
  -- Explicit 'UTC' arg keeps the chain seed independent of session TZ.
  SELECT row_hash INTO prev FROM agent_audit_log
    WHERE ts >= date_trunc('day', NEW.ts, 'UTC')
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
