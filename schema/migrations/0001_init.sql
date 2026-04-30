-- agent-auth schema v1.0
-- Run as agent_auth_migrator role
-- Idempotent: re-running has no effect

BEGIN;

-- ============================================================================
-- Type domains (enums)
-- ============================================================================

CREATE DOMAIN tier_enum AS TEXT
  CHECK (VALUE IN ('cold', 'warm', 'hot'));

CREATE DOMAIN account_status_enum AS TEXT
  CHECK (VALUE IN ('active', 'suspended', 'closed'));

CREATE DOMAIN identity_status_enum AS TEXT
  CHECK (VALUE IN ('active', 'revoked', 'expired'));

CREATE DOMAIN revocation_source_enum AS TEXT
  CHECK (VALUE IS NULL OR VALUE IN ('webhook', 'expiry', 'manual', 'cascade', 'admin'));

CREATE DOMAIN assurance_level_enum AS TEXT
  CHECK (VALUE IN ('low', 'medium', 'high'));

CREATE DOMAIN rotation_state_enum AS TEXT
  CHECK (VALUE IN ('active', 'rotating', 'rotated', 'revoked'));

CREATE DOMAIN session_status_enum AS TEXT
  CHECK (VALUE IN ('pending', 'exchanging', 'ready', 'failed', 'expired'));

CREATE DOMAIN session_kind_enum AS TEXT
  CHECK (VALUE IN ('register', 'recover', 'add_key', 'revalidate'));

CREATE DOMAIN idempotency_state_enum AS TEXT
  CHECK (VALUE IN ('pending', 'completed', 'failed', 'unknown', 'manual_required'));

-- ============================================================================
-- Roles (idempotent)
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
END $$;

-- ============================================================================
-- Tables (full DDL — see SPEC.md Part III for narrative)
-- ============================================================================

CREATE TABLE agent_accounts (
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
CREATE INDEX agent_accounts_status_active ON agent_accounts(status) WHERE status = 'active';
CREATE INDEX agent_accounts_tier ON agent_accounts(tier) WHERE status = 'active';

CREATE OR REPLACE FUNCTION trigger_set_updated_at() RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_accounts_updated_at
  BEFORE UPDATE ON agent_accounts
  FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();

CREATE TABLE agent_identities (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,
  subject             TEXT NOT NULL,
  audience            TEXT NOT NULL,
  issuer              TEXT NOT NULL,
  assurance_level    assurance_level_enum NOT NULL,
  display_handle     TEXT,
  is_primary         BOOLEAN NOT NULL DEFAULT false,
  status             identity_status_enum NOT NULL DEFAULT 'active',
  revoked_at         TIMESTAMPTZ,
  revoked_reason     TEXT,
  revocation_source  revocation_source_enum,
  verified_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_revalidated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata           JSONB,
  CONSTRAINT identities_revocation_consistent
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CONSTRAINT identities_revoked_has_source
    CHECK (status != 'revoked' OR revocation_source IS NOT NULL)
);
CREATE UNIQUE INDEX agent_identities_unique_active ON agent_identities(provider, subject, audience);
CREATE UNIQUE INDEX agent_identities_one_primary_per_account
  ON agent_identities(account_id) WHERE is_primary AND status = 'active';
CREATE INDEX agent_identities_account_active
  ON agent_identities(account_id) WHERE status = 'active';

CREATE TABLE agent_api_keys (
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
CREATE INDEX agent_api_keys_active_lookup
  ON agent_api_keys(key_id) WHERE rotation_state IN ('active', 'rotating');
CREATE UNIQUE INDEX agent_api_keys_one_predecessor
  ON agent_api_keys(created_by_key_id) WHERE created_by_key_id IS NOT NULL;
CREATE UNIQUE INDEX agent_api_keys_one_successor
  ON agent_api_keys(replaced_by_key_id) WHERE replaced_by_key_id IS NOT NULL;
CREATE INDEX agent_api_keys_account ON agent_api_keys(account_id);
CREATE INDEX agent_api_keys_identity ON agent_api_keys(issued_via_identity_id);
COMMENT ON COLUMN agent_api_keys.last_revoke_lsn IS
  'Optimization: per-key barrier. NOT a correctness gate.
   Correctness uses agent_revocation_barrier.last_lsn (global authoritative).';

-- Trigger: enforce 1:1 inverse on rotation
CREATE OR REPLACE FUNCTION enforce_rotation_inverse() RETURNS TRIGGER AS $$
DECLARE rows_updated INT;
BEGIN
  IF NEW.created_by_key_id IS NOT NULL THEN
    UPDATE agent_api_keys
      SET replaced_by_key_id = NEW.id
      WHERE id = NEW.created_by_key_id AND replaced_by_key_id IS NULL;
    GET DIAGNOSTICS rows_updated = ROW_COUNT;
    IF rows_updated = 0 THEN
      RAISE EXCEPTION 'rotation_inverse_violation: predecessor % already replaced or missing', NEW.created_by_key_id
        USING ERRCODE = 'unique_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_enforce_rotation_inverse
  AFTER INSERT ON agent_api_keys
  FOR EACH ROW EXECUTE FUNCTION enforce_rotation_inverse();

-- Trigger: sync account.tier → keys.tier on tier change
CREATE OR REPLACE FUNCTION sync_account_tier_to_keys() RETURNS TRIGGER AS $$
DECLARE affected_key_ids TEXT[];
BEGIN
  UPDATE agent_api_keys
    SET tier = NEW.tier, version = version + 1
    WHERE account_id = NEW.id AND rotation_state IN ('active', 'rotating')
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

-- Sessions, device flows, audit log, webhook events, replay state, idempotency, etc.
-- (See SPEC.md Part III sections 3.6-3.16 for full DDL — extracted to subsequent migrations
-- when the lib codebase is initialized.)

-- ============================================================================
-- Permissions
-- ============================================================================

GRANT USAGE ON SCHEMA public TO agent_auth_app, agent_auth_admin, agent_auth_readonly;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO agent_auth_app;
-- Audit log: app gets INSERT only
-- (REVOKE happens after agent_audit_log is created in 0002_audit_partitions.sql)

GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agent_auth_admin;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_auth_readonly;

COMMIT;

-- For full schema (audit log partitions, idempotency, sessions, etc.), see migrations 0002+
-- and SPEC.md Part III.
