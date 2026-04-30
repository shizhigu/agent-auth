-- Rollback for 0001_init.sql. SPEC §3.17.
-- Run as agent_auth_migrator. ORDER MATTERS — drop FK-dependent tables first.

BEGIN;

DROP TRIGGER IF EXISTS trigger_sync_account_tier ON agent_accounts;
DROP TRIGGER IF EXISTS trigger_enforce_rotation_inverse ON agent_api_keys;
DROP TRIGGER IF EXISTS agent_accounts_updated_at ON agent_accounts;

DROP FUNCTION IF EXISTS sync_account_tier_to_keys();
DROP FUNCTION IF EXISTS enforce_rotation_inverse();
DROP FUNCTION IF EXISTS trigger_set_updated_at();

DROP TABLE IF EXISTS agent_device_flows;
DROP TABLE IF EXISTS agent_registration_sessions;
DROP TABLE IF EXISTS agent_api_keys;
DROP TABLE IF EXISTS agent_identities;
DROP TABLE IF EXISTS agent_accounts;
DROP TABLE IF EXISTS agent_jobs;

-- Drop type domains (must be after tables that reference them).
DROP DOMAIN IF EXISTS idempotency_state_enum;
DROP DOMAIN IF EXISTS session_kind_enum;
DROP DOMAIN IF EXISTS session_status_enum;
DROP DOMAIN IF EXISTS rotation_state_enum;
DROP DOMAIN IF EXISTS assurance_level_enum;
DROP DOMAIN IF EXISTS revocation_source_enum;
DROP DOMAIN IF EXISTS identity_status_enum;
DROP DOMAIN IF EXISTS account_status_enum;
DROP DOMAIN IF EXISTS tier_enum;

-- Roles deliberately left in place — they may be granted to LOGIN users
-- outside this lib's control (per §11.5). Operators DROP them by hand
-- after confirming no users depend on them.

COMMIT;
