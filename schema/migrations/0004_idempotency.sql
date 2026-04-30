-- agent-auth schema — idempotency framework
-- SPEC.md §3.13, §5.1.
-- Run as agent_auth_migrator. Idempotent.

BEGIN;

-- ============================================================================
-- agent_idempotency — §3.13. State machine + terminal-row immutability.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_idempotency (
  key                  TEXT PRIMARY KEY,
  request_hash         BYTEA NOT NULL,
  operation_type       TEXT NOT NULL,
  resource_ref         TEXT NOT NULL,
  outcome_status       INT,
  outcome_body         JSONB,
  state                idempotency_state_enum NOT NULL DEFAULT 'pending',
  reconcile_attempts   INT NOT NULL DEFAULT 0,
  last_reconcile_at    TIMESTAMPTZ,
  manual_required_at   TIMESTAMPTZ,
  expires_at           TIMESTAMPTZ NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_idempotency_state
  ON agent_idempotency(state)
  WHERE state IN ('pending', 'unknown');
CREATE INDEX IF NOT EXISTS agent_idempotency_expires
  ON agent_idempotency(expires_at);

-- Trigger: monotonic state transitions (§5.1.1).
-- pending -> {completed, failed, unknown}
-- unknown -> {completed, failed, manual_required}
-- {completed, failed, manual_required} -> terminal (no further transitions
--   except via admin override which is itself logged).
CREATE OR REPLACE FUNCTION enforce_idempotency_transitions() RETURNS TRIGGER AS $$
DECLARE
  allowed BOOLEAN := false;
BEGIN
  IF OLD.state = NEW.state THEN
    RETURN NEW;
  END IF;

  IF OLD.state = 'pending' THEN
    allowed := NEW.state IN ('completed', 'failed', 'unknown');
  ELSIF OLD.state = 'unknown' THEN
    allowed := NEW.state IN ('completed', 'failed', 'manual_required');
  ELSIF OLD.state IN ('completed', 'failed', 'manual_required') THEN
    allowed := false;
  END IF;

  IF NOT allowed AND current_user = 'agent_auth_admin' THEN
    INSERT INTO agent_audit_log (ts, event_type, meta, status_class)
    VALUES (now(), 'idempotency_admin_override',
            jsonb_build_object('key', NEW.key, 'from', OLD.state, 'to', NEW.state),
            2);
    allowed := true;
  END IF;

  IF NOT allowed THEN
    RAISE EXCEPTION 'idempotency_invalid_transition: % -> %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_idempotency_transitions ON agent_idempotency;
CREATE TRIGGER trigger_idempotency_transitions
  BEFORE UPDATE OF state ON agent_idempotency
  FOR EACH ROW EXECUTE FUNCTION enforce_idempotency_transitions();

-- Trigger: terminal-row immutability (everything except `state`).
CREATE OR REPLACE FUNCTION enforce_terminal_row_immutable() RETURNS TRIGGER AS $$
BEGIN
  IF OLD.state IN ('completed', 'failed', 'manual_required') THEN
    IF (OLD.request_hash, OLD.outcome_status, OLD.outcome_body,
        OLD.resource_ref, OLD.operation_type)
       IS DISTINCT FROM
       (NEW.request_hash, NEW.outcome_status, NEW.outcome_body,
        NEW.resource_ref, NEW.operation_type) THEN
      RAISE EXCEPTION 'idempotency_terminal_row_immutable'
        USING ERRCODE = 'check_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_idempotency_terminal_immutable ON agent_idempotency;
CREATE TRIGGER trigger_idempotency_terminal_immutable
  BEFORE UPDATE ON agent_idempotency
  FOR EACH ROW EXECUTE FUNCTION enforce_terminal_row_immutable();

GRANT SELECT, INSERT, UPDATE ON agent_idempotency TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_idempotency TO agent_auth_admin;
GRANT SELECT ON agent_idempotency TO agent_auth_readonly;

COMMIT;
