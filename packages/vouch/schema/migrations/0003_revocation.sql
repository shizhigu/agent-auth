-- agent-auth schema — revocation log + epoch + barrier + recovery approvals
-- SPEC.md §3.11, §3.12, §3.14.
-- Run as agent_auth_migrator. Idempotent.

BEGIN;

-- ============================================================================
-- agent_revocation_log — §3.11. Append-only cross-region revocation log.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_revocation_log (
  id                       BIGSERIAL PRIMARY KEY,
  ts                       TIMESTAMPTZ NOT NULL DEFAULT now(),
  region                   TEXT NOT NULL,
  kind                     TEXT NOT NULL
                           CHECK (kind IN ('key_revoke', 'account_suspend',
                                           'identity_revoke', 'emergency_rotate',
                                           'account_close')),
  target_id                TEXT NOT NULL,
  commit_lsn               pg_lsn NOT NULL,
  epoch                    BIGINT NOT NULL,
  reason                   TEXT,
  replicated_to_regions    TEXT[]
);

CREATE INDEX IF NOT EXISTS agent_revocation_log_lsn
  ON agent_revocation_log(commit_lsn);
CREATE INDEX IF NOT EXISTS agent_revocation_log_target
  ON agent_revocation_log(target_id);

GRANT SELECT, INSERT ON agent_revocation_log TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_revocation_log TO agent_auth_admin;
GRANT SELECT ON agent_revocation_log TO agent_auth_readonly;
GRANT USAGE, SELECT ON SEQUENCE agent_revocation_log_id_seq
  TO agent_auth_app, agent_auth_admin;

-- ============================================================================
-- agent_revocation_epoch — §3.12. Singleton; monotonic.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_revocation_epoch (
  id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  epoch       BIGINT NOT NULL DEFAULT 0,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO agent_revocation_epoch (id, epoch) VALUES (1, 0)
  ON CONFLICT (id) DO NOTHING;

-- Trigger: epoch can only increase (monotonic).
CREATE OR REPLACE FUNCTION enforce_epoch_monotonic() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.epoch <= OLD.epoch THEN
    RAISE EXCEPTION 'epoch_non_monotonic: % <= %', NEW.epoch, OLD.epoch
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_epoch_monotonic ON agent_revocation_epoch;
CREATE TRIGGER trigger_epoch_monotonic
  BEFORE UPDATE OF epoch ON agent_revocation_epoch
  FOR EACH ROW EXECUTE FUNCTION enforce_epoch_monotonic();

GRANT SELECT, UPDATE ON agent_revocation_epoch TO agent_auth_app;
GRANT SELECT, UPDATE ON agent_revocation_epoch TO agent_auth_admin;
GRANT SELECT ON agent_revocation_epoch TO agent_auth_readonly;

-- ============================================================================
-- agent_revocation_barrier — §3.12. Singleton; LSN advances post-commit.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_revocation_barrier (
  id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_lsn    pg_lsn NOT NULL,
  timeline_id INT NOT NULL DEFAULT 1,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO agent_revocation_barrier (id, last_lsn, timeline_id)
  VALUES (1, '0/0', 1)
  ON CONFLICT (id) DO NOTHING;

-- Trigger: barrier LSN may advance OR (on failover) be reset to a fresh LSN
-- on a new timeline. Reset is allowed only when timeline_id changes.
-- Within a timeline, last_lsn must be monotonic non-decreasing.
CREATE OR REPLACE FUNCTION enforce_barrier_monotonic() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.timeline_id = OLD.timeline_id AND NEW.last_lsn < OLD.last_lsn THEN
    RAISE EXCEPTION 'barrier_lsn_regressed_in_timeline: % < % (timeline %)',
      NEW.last_lsn, OLD.last_lsn, OLD.timeline_id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.timeline_id < OLD.timeline_id THEN
    RAISE EXCEPTION 'barrier_timeline_regressed: % < %',
      NEW.timeline_id, OLD.timeline_id
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_barrier_monotonic ON agent_revocation_barrier;
CREATE TRIGGER trigger_barrier_monotonic
  BEFORE UPDATE ON agent_revocation_barrier
  FOR EACH ROW EXECUTE FUNCTION enforce_barrier_monotonic();

GRANT SELECT, UPDATE ON agent_revocation_barrier TO agent_auth_app;
GRANT SELECT, UPDATE ON agent_revocation_barrier TO agent_auth_admin;
GRANT SELECT ON agent_revocation_barrier TO agent_auth_readonly;

-- ============================================================================
-- agent_recovery_approvals — §3.14. Two-person rule for high-value recovery.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_recovery_approvals (
  request_id          UUID PRIMARY KEY,
  account_id          UUID NOT NULL REFERENCES agent_accounts(id),
  poll_token          TEXT NOT NULL UNIQUE,
  approval_url_token  TEXT NOT NULL UNIQUE,
  webhook_nonce       BYTEA NOT NULL,
  webhook_sent_at     TIMESTAMPTZ NOT NULL,
  decision            TEXT CHECK (decision IN ('pending','approved','denied')),
  decision_at         TIMESTAMPTZ,
  decision_reason     TEXT,
  expires_at          TIMESTAMPTZ NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_recovery_approvals_pending
  ON agent_recovery_approvals(expires_at)
  WHERE decision IS NULL OR decision = 'pending';

GRANT SELECT, INSERT, UPDATE ON agent_recovery_approvals TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_recovery_approvals TO agent_auth_admin;
GRANT SELECT ON agent_recovery_approvals TO agent_auth_readonly;

COMMIT;
