-- agent-auth schema v1.0 — base migration
-- SPEC.md Part III §3.2-3.5, §3.6-3.7, §3.15, §3.16, §3.17.
-- Run as agent_auth_migrator. Idempotent: re-running has no effect.

BEGIN;

-- ============================================================================
-- Extensions
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;       -- digest() for audit hash chain (§3.8 / 0002)

-- ============================================================================
-- Type domains (enums) — §3.2
-- ============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tier_enum') THEN
    CREATE DOMAIN tier_enum AS TEXT
      CHECK (VALUE IN ('cold', 'warm', 'hot'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'account_status_enum') THEN
    CREATE DOMAIN account_status_enum AS TEXT
      CHECK (VALUE IN ('active', 'suspended', 'closed'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'identity_status_enum') THEN
    CREATE DOMAIN identity_status_enum AS TEXT
      CHECK (VALUE IN ('active', 'revoked', 'expired'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'revocation_source_enum') THEN
    CREATE DOMAIN revocation_source_enum AS TEXT
      CHECK (VALUE IS NULL OR VALUE IN ('webhook', 'expiry', 'manual', 'cascade', 'admin'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'assurance_level_enum') THEN
    CREATE DOMAIN assurance_level_enum AS TEXT
      CHECK (VALUE IN ('low', 'medium', 'high'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'rotation_state_enum') THEN
    CREATE DOMAIN rotation_state_enum AS TEXT
      CHECK (VALUE IN ('active', 'rotating', 'rotated', 'revoked'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_status_enum') THEN
    CREATE DOMAIN session_status_enum AS TEXT
      CHECK (VALUE IN ('pending', 'exchanging', 'ready', 'failed', 'expired'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'session_kind_enum') THEN
    CREATE DOMAIN session_kind_enum AS TEXT
      CHECK (VALUE IN ('register', 'recover', 'add_key', 'revalidate'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'idempotency_state_enum') THEN
    CREATE DOMAIN idempotency_state_enum AS TEXT
      CHECK (VALUE IN ('pending', 'completed', 'failed', 'unknown', 'manual_required'));
  END IF;
END $$;

-- ============================================================================
-- Roles — §3.16, §11.5
-- Idempotent. Real password assignment + LOGIN users belong to deployment scripts.
-- ============================================================================

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_auth_app') THEN
    CREATE ROLE agent_auth_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_auth_admin') THEN
    CREATE ROLE agent_auth_admin NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_auth_readonly') THEN
    CREATE ROLE agent_auth_readonly NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_auth_migrator') THEN
    CREATE ROLE agent_auth_migrator NOLOGIN;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO agent_auth_app, agent_auth_admin, agent_auth_readonly;
GRANT CREATE ON SCHEMA public TO agent_auth_migrator;

-- ============================================================================
-- Generic helpers
-- ============================================================================

CREATE OR REPLACE FUNCTION trigger_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- agent_jobs — §3.15. Defined first because §3.5 trigger inserts into it.
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_jobs (
  id           BIGSERIAL PRIMARY KEY,
  kind         TEXT NOT NULL,
  payload      JSONB NOT NULL,
  run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts     INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'running', 'completed', 'failed', 'dead')),
  last_error   TEXT,
  locked_at    TIMESTAMPTZ,
  locked_by    TEXT,
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS agent_jobs_runnable
  ON agent_jobs(run_at, kind)
  WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS agent_jobs_stuck
  ON agent_jobs(locked_at)
  WHERE status = 'running';

-- ============================================================================
-- agent_accounts — §3.3
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_accounts (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  display_handle      TEXT,
  tier                tier_enum NOT NULL DEFAULT 'cold',
  tier_changed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  tier_change_reason  TEXT,
  risk_score          REAL NOT NULL DEFAULT 0.5
                      CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
  status              account_status_enum NOT NULL DEFAULT 'active',
  suspended_at        TIMESTAMPTZ,
  closed_at           TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_accounts_status_active
  ON agent_accounts(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS agent_accounts_tier
  ON agent_accounts(tier) WHERE status = 'active';

DROP TRIGGER IF EXISTS agent_accounts_updated_at ON agent_accounts;
CREATE TRIGGER agent_accounts_updated_at
  BEFORE UPDATE ON agent_accounts
  FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

-- ============================================================================
-- agent_identities — §3.4
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_identities (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,
  subject             TEXT NOT NULL,
  audience            TEXT NOT NULL,
  issuer              TEXT NOT NULL,
  assurance_level     assurance_level_enum NOT NULL,
  display_handle      TEXT,
  is_primary          BOOLEAN NOT NULL DEFAULT false,
  status              identity_status_enum NOT NULL DEFAULT 'active',
  revoked_at          TIMESTAMPTZ,
  revoked_reason      TEXT,
  revocation_source   revocation_source_enum,
  verified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_revalidated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata            JSONB,
  CONSTRAINT identities_revocation_consistent
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT identities_revoked_has_source
    CHECK (status != 'revoked' OR revocation_source IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_identities_unique_active
  ON agent_identities(provider, subject, audience);
CREATE UNIQUE INDEX IF NOT EXISTS agent_identities_one_primary_per_account
  ON agent_identities(account_id) WHERE is_primary AND status = 'active';
CREATE INDEX IF NOT EXISTS agent_identities_account_active
  ON agent_identities(account_id) WHERE status = 'active';

-- ============================================================================
-- agent_api_keys — §3.5
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_api_keys (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id                  UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  issued_via_identity_id      UUID NOT NULL REFERENCES agent_identities(id),
  key_id                      TEXT NOT NULL UNIQUE,
  key_hash                    BYTEA NOT NULL,
  key_pepper_version          INT NOT NULL DEFAULT 1,
  prefix                      TEXT NOT NULL,
  label                       TEXT,
  scopes                      TEXT[] NOT NULL DEFAULT '{}',
  tier                        tier_enum NOT NULL DEFAULT 'cold',
  version                     INT NOT NULL DEFAULT 1,
  expires_at                  TIMESTAMPTZ,
  last_used_at                TIMESTAMPTZ,
  rotation_state              rotation_state_enum NOT NULL DEFAULT 'active',
  rotated_at                  TIMESTAMPTZ,
  rotation_grace_expires_at   TIMESTAMPTZ,
  replaced_by_key_id          UUID REFERENCES agent_api_keys(id),
  created_by_key_id           UUID REFERENCES agent_api_keys(id),
  revoked_at                  TIMESTAMPTZ,
  revoked_reason              TEXT,
  last_revoke_lsn             pg_lsn,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT keys_revoked_state_consistent
    CHECK ((rotation_state = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT keys_rotated_has_grace
    CHECK (rotation_state != 'rotating' OR rotation_grace_expires_at IS NOT NULL),
  CONSTRAINT keys_self_reference_prevented
    CHECK (replaced_by_key_id IS NULL OR replaced_by_key_id != id),
  CONSTRAINT keys_self_reference_prevented_2
    CHECK (created_by_key_id IS NULL OR created_by_key_id != id)
);

CREATE INDEX IF NOT EXISTS agent_api_keys_active_lookup
  ON agent_api_keys(key_id) WHERE rotation_state IN ('active', 'rotating');
CREATE UNIQUE INDEX IF NOT EXISTS agent_api_keys_one_predecessor
  ON agent_api_keys(created_by_key_id) WHERE created_by_key_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS agent_api_keys_one_successor
  ON agent_api_keys(replaced_by_key_id) WHERE replaced_by_key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS agent_api_keys_account ON agent_api_keys(account_id);
CREATE INDEX IF NOT EXISTS agent_api_keys_identity
  ON agent_api_keys(issued_via_identity_id);

COMMENT ON COLUMN agent_api_keys.last_revoke_lsn IS
  'Optimization: per-key barrier. NOT a correctness gate.
   Correctness uses agent_revocation_barrier.last_lsn (global authoritative).';

-- Trigger: enforce 1:1 inverse on rotation (§3.5)
CREATE OR REPLACE FUNCTION enforce_rotation_inverse() RETURNS TRIGGER AS $$
DECLARE
  rows_updated INT;
BEGIN
  IF NEW.created_by_key_id IS NOT NULL THEN
    UPDATE agent_api_keys
      SET replaced_by_key_id = NEW.id
      WHERE id = NEW.created_by_key_id AND replaced_by_key_id IS NULL;
    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    IF rows_updated = 0 THEN
      RAISE EXCEPTION 'rotation_inverse_violation: predecessor % already replaced or missing',
        NEW.created_by_key_id
        USING ERRCODE = 'unique_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_enforce_rotation_inverse ON agent_api_keys;
CREATE TRIGGER trigger_enforce_rotation_inverse
  AFTER INSERT ON agent_api_keys
  FOR EACH ROW EXECUTE FUNCTION enforce_rotation_inverse();

-- Trigger: sync account.tier → keys.tier on tier change (§3.5)
CREATE OR REPLACE FUNCTION sync_account_tier_to_keys() RETURNS TRIGGER AS $$
DECLARE
  affected_key_ids TEXT[];
BEGIN
  UPDATE agent_api_keys
    SET tier = NEW.tier, version = version + 1
    WHERE account_id = NEW.id
      AND rotation_state IN ('active', 'rotating')
    RETURNING ARRAY_AGG(key_id) INTO affected_key_ids;

  IF affected_key_ids IS NOT NULL AND array_length(affected_key_ids, 1) > 0 THEN
    INSERT INTO agent_jobs (kind, payload, run_at)
    VALUES ('cache_invalidate_keys',
            jsonb_build_object('key_ids', affected_key_ids,
                              'reason', 'tier_change',
                              'new_tier', NEW.tier),
            now());
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_sync_account_tier ON agent_accounts;
CREATE TRIGGER trigger_sync_account_tier
  AFTER UPDATE OF tier ON agent_accounts
  FOR EACH ROW
  WHEN (OLD.tier IS DISTINCT FROM NEW.tier)
  EXECUTE FUNCTION sync_account_tier_to_keys();

-- ============================================================================
-- agent_registration_sessions — §3.6
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_registration_sessions (
  poll_token         TEXT PRIMARY KEY,
  nonce              TEXT NOT NULL UNIQUE,
  pkce_verifier      TEXT NOT NULL,
  pkce_challenge     TEXT NOT NULL,
  audience           TEXT NOT NULL,
  expected_provider  TEXT NOT NULL,
  redirect_uri       TEXT NOT NULL,
  kind               session_kind_enum NOT NULL,
  target_account_id  UUID REFERENCES agent_accounts(id),
  client_pubkey      BYTEA NOT NULL,
  status             session_status_enum NOT NULL DEFAULT 'pending',
  status_message     TEXT,
  result_ciphertext  BYTEA,
  account_id         UUID REFERENCES agent_accounts(id),
  expires_at         TIMESTAMPTZ NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT poll_token_prefix_matches_kind CHECK (
    (kind = 'register'   AND poll_token ~ '^pak_[A-Za-z0-9_-]{43}$') OR
    (kind = 'recover'    AND poll_token ~ '^pkr_[A-Za-z0-9_-]{43}$') OR
    (kind = 'add_key'    AND poll_token ~ '^pad_[A-Za-z0-9_-]{43}$') OR
    (kind = 'revalidate' AND poll_token ~ '^pav_[A-Za-z0-9_-]{43}$')
  ),
  CONSTRAINT recovery_target_required CHECK (
    (kind != 'recover' AND kind != 'revalidate') OR (target_account_id IS NOT NULL)
  ),
  CONSTRAINT client_pubkey_size CHECK (octet_length(client_pubkey) = 32)
);

CREATE INDEX IF NOT EXISTS agent_reg_sessions_active
  ON agent_registration_sessions(expires_at)
  WHERE status IN ('pending', 'ready');

-- ============================================================================
-- agent_device_flows — §3.7
-- ============================================================================

CREATE TABLE IF NOT EXISTS agent_device_flows (
  device_code_hash       BYTEA PRIMARY KEY,
  device_code_encrypted  BYTEA NOT NULL,
  device_code_iv         BYTEA NOT NULL,
  user_code              TEXT NOT NULL,
  verification_uri       TEXT NOT NULL,
  expires_at             TIMESTAMPTZ NOT NULL,
  poll_interval_seconds  INT NOT NULL DEFAULT 5,
  next_poll_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  poll_token             TEXT NOT NULL UNIQUE
                         REFERENCES agent_registration_sessions(poll_token),
  status                 TEXT NOT NULL DEFAULT 'pending'
                         CHECK (status IN ('pending', 'authorized', 'denied', 'expired')),
  attempts               INT NOT NULL DEFAULT 0,
  last_error             TEXT,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_device_flows_polling
  ON agent_device_flows(next_poll_at, status)
  WHERE status = 'pending';

-- ============================================================================
-- Permissions — §3.16
-- (audit_log + idempotency adjust permissions in their own migrations)
-- ============================================================================

GRANT SELECT, INSERT, UPDATE ON
  agent_jobs, agent_accounts, agent_identities, agent_api_keys,
  agent_registration_sessions, agent_device_flows
  TO agent_auth_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  agent_jobs, agent_accounts, agent_identities, agent_api_keys,
  agent_registration_sessions, agent_device_flows
  TO agent_auth_admin;

GRANT SELECT ON
  agent_jobs, agent_accounts, agent_identities, agent_api_keys,
  agent_registration_sessions, agent_device_flows
  TO agent_auth_readonly;

GRANT USAGE, SELECT ON SEQUENCE agent_jobs_id_seq TO agent_auth_app, agent_auth_admin;

COMMIT;
