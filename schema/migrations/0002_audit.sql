-- agent-auth schema — audit log + webhook events
-- SPEC.md §3.8 (audit_log partitioned + hash chain), §3.9 (webhook_events),
-- §3.10 (webhook_replay_state), §6.4.2 (audit_outbox).
-- Run as agent_auth_migrator. Idempotent.

BEGIN;

-- ============================================================================
-- agent_audit_log — §3.8: partitioned, hash-chained, append-only
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_audit_log (
  id           BIGSERIAL,
  ts           TIMESTAMPTZ NOT NULL,
  account_id   UUID,
  key_id       TEXT,
  identity_id  UUID,
  event_type   TEXT NOT NULL,
  endpoint     TEXT,
  ip_hash      BYTEA,                          -- HMAC-SHA256(ip, internal_secret)
  asn          INT,
  user_agent   TEXT,
  status_class INT,                            -- 2 / 3 / 4 / 5
  cost_units   INT NOT NULL DEFAULT 1,
  meta         JSONB,                          -- scrubbed by lib (§6.6)
  prev_hash    BYTEA,                          -- previous row's row_hash
  row_hash     BYTEA,                          -- SHA-256(prev_hash || canonical(this row))
  PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- Default catch-all partition; daily partitions are created by lib's scheduler.
CREATE TABLE IF NOT EXISTS agent_audit_log_default
  PARTITION OF agent_audit_log DEFAULT;

CREATE INDEX IF NOT EXISTS agent_audit_account_ts
  ON agent_audit_log USING BRIN (account_id, ts);
CREATE INDEX IF NOT EXISTS agent_audit_key_ts
  ON agent_audit_log USING BRIN (key_id, ts);
CREATE INDEX IF NOT EXISTS agent_audit_event_ts
  ON agent_audit_log USING BRIN (event_type, ts);

-- Hash chain trigger — §3.8 / §6.4.1
CREATE OR REPLACE FUNCTION compute_audit_row_hash() RETURNS TRIGGER AS $$
DECLARE
  prev BYTEA;
  canonical TEXT;
BEGIN
  -- Previous row in the same UTC-day window (or 0x00...00 for first row).
  SELECT row_hash INTO prev FROM agent_audit_log
    WHERE ts >= date_trunc('day', NEW.ts)
    ORDER BY id DESC LIMIT 1;
  IF prev IS NULL THEN
    prev = decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
  END IF;

  NEW.prev_hash = prev;

  -- Canonical form: stable key order + sha256 over meta to keep chain hash bounded.
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

DROP TRIGGER IF EXISTS trigger_audit_hash_chain ON agent_audit_log;
CREATE TRIGGER trigger_audit_hash_chain
  BEFORE INSERT ON agent_audit_log
  FOR EACH ROW EXECUTE FUNCTION compute_audit_row_hash();

-- App role: append-only — INSERT and SELECT (needed for INSERT...RETURNING
-- and for in-process verifyChain to read its own writes). UPDATE and DELETE
-- are NOT granted, preserving the §3.16 append-only invariant.
GRANT INSERT, SELECT ON agent_audit_log TO agent_auth_app;
GRANT USAGE, SELECT ON SEQUENCE agent_audit_log_id_seq
  TO agent_auth_app, agent_auth_admin;

-- Admin role can read everything; UPDATE for partition drop / RB-6
-- restoration; INSERT so triggers (e.g. enforce_idempotency_transitions
-- admin override path) can append override events. DELETE is reserved
-- for partition retention and is itself logged.
GRANT SELECT, INSERT, UPDATE ON agent_audit_log TO agent_auth_admin;

-- Read-only role: column-restricted to non-PII columns (per §3.16).
GRANT SELECT (id, ts, event_type, account_id, key_id, status_class)
  ON agent_audit_log TO agent_auth_readonly;

-- ============================================================================
-- agent_webhook_events — §3.9
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_webhook_events (
  id              UUID PRIMARY KEY,             -- X-GitHub-Delivery
  provider        TEXT NOT NULL,
  event_type      TEXT NOT NULL,
  payload_hash    BYTEA NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at    TIMESTAMPTZ,
  status          TEXT NOT NULL DEFAULT 'received'
                  CHECK (status IN ('received', 'processed', 'failed', 'ignored')),
  error           TEXT,
  payload_snippet JSONB
);

CREATE INDEX IF NOT EXISTS agent_webhook_events_unprocessed
  ON agent_webhook_events(received_at)
  WHERE status IN ('received', 'failed');
CREATE INDEX IF NOT EXISTS agent_webhook_events_provider_received
  ON agent_webhook_events(provider, received_at);

GRANT SELECT, INSERT, UPDATE ON agent_webhook_events TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_webhook_events TO agent_auth_admin;
GRANT SELECT ON agent_webhook_events TO agent_auth_readonly;

-- ============================================================================
-- agent_webhook_replay_state — §3.10
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_webhook_replay_state (
  provider                       TEXT PRIMARY KEY,
  last_seen_delivery_id          TEXT,
  last_run_at                    TIMESTAMPTZ,
  last_run_status                TEXT
                                  CHECK (last_run_status IN ('ok','partial','failed','cap_hit')),
  catch_up_pages                 INT NOT NULL DEFAULT 0,
  total_redelivered              BIGINT NOT NULL DEFAULT 0,
  config_max_pages               INT NOT NULL DEFAULT 10,
  config_lookback_hours          INT NOT NULL DEFAULT 72,
  config_poll_interval_seconds   INT NOT NULL DEFAULT 300
);

INSERT INTO agent_webhook_replay_state (provider) VALUES ('github_app')
  ON CONFLICT (provider) DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON agent_webhook_replay_state TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_webhook_replay_state TO agent_auth_admin;
GRANT SELECT ON agent_webhook_replay_state TO agent_auth_readonly;

-- ============================================================================
-- agent_audit_outbox — §6.4.2 (referenced by writeAudit() retry path)
-- Holds events whose WORM PutObject failed; flushed by outbox-flusher job.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_audit_outbox (
  id          BIGSERIAL PRIMARY KEY,
  event_id    BIGINT NOT NULL,                    -- FK-soft to agent_audit_log.id
  payload     JSONB NOT NULL,
  attempts    INT NOT NULL DEFAULT 0,
  last_error  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  flushed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS agent_audit_outbox_pending
  ON agent_audit_outbox(created_at) WHERE flushed_at IS NULL;

GRANT SELECT, INSERT, UPDATE ON agent_audit_outbox TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON agent_audit_outbox TO agent_auth_admin;
GRANT USAGE, SELECT ON SEQUENCE agent_audit_outbox_id_seq
  TO agent_auth_app, agent_auth_admin;

COMMIT;
