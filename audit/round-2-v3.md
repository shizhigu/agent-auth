# agent-auth v3 design spec (post round-2 audit)

This is implementation-ready spec. Addresses all 8 critical findings from round-2 codex audit, plus protocol-level details v2 underspecified. Goal: AI coding agent should implement this without re-asking for clarification.

## Problem statement (unchanged from v2)

A SaaS provider wants to let AI agents (Claude Code, Cursor, etc.) register accounts on behalf of a human user programmatically. Today blocked by CAPTCHA / email click / SMS. This library mounts as a parallel auth rail next to existing human auth, never replacing it.

## Critical changes from v2

| Round-2 finding | v3 fix |
|---|---|
| 1. GitHub flow underspecified | Server-side code exchange ONLY. Lib never accepts raw GitHub tokens or auth codes from agents. PKCE `code_verifier` + `client_secret` + exact `redirect_uri` are mandatory. |
| 2. Key delivery via callback leaks | `/begin-registration` returns `poll_token`. Callback only marks session ready. Agent polls `/registration-status` to get key over its own channel. |
| 3. Registration not idempotent | One-time secret stored encrypted under `poll_token` with TTL 5min. Cleared on first successful retrieval. Replay within window returns same secret. |
| 4. Rotation race | `agent_api_keys` adds `rotated_at`, `rotation_state`, `replaced_by_key_id`, `created_by_key_id`. `/rotate-key` uses `SELECT FOR UPDATE`. Unique partial index prevents multiple successors. |
| 5. Identity revocation not modeled | `agent_identities` adds `status`, `revoked_at`, `revoked_reason`, `revocation_source`. GitHub `github_app_authorization` webhook → cascade. |
| 6. Multi-agent UX | New `POST /issue-key` requires fresh OAuth proof. `/recover-account` is owner-gated. Recovery destroys old keys; issue-key keeps them. |
| 7. Redis cluster atomicity | v0.1: single Redis primary. Hash-tagged keys for future cluster mode. Non-atomic dimensions explicitly listed. |
| 8. Cache invalidation backstop | 30s TTL is the v0.1 worst-case revocation latency. Pubsub invalidation is best-effort. Documented. |

## Architecture

```
SaaS backend (existing)
├── Existing human auth (untouched)
└── agent-auth library
    ├── Public endpoints
    │   GET  /.well-known/agent-auth
    │   POST /api/agent-auth/begin-registration
    │   POST /api/agent-auth/registration-status
    │   POST /api/agent-auth/issue-key
    │   POST /api/agent-auth/rotate-key
    │   POST /api/agent-auth/revoke
    │   POST /api/agent-auth/recover-account
    │   GET  /api/agent-auth/keys
    ├── Internal callback (consumed by upstream IdPs only)
    │   GET  /api/agent-auth/callback/:provider
    ├── Webhooks (consumed by upstream IdPs)
    │   POST /api/agent-auth/webhooks/:provider
    └── Middleware (mounted on protected routes)
         agents.middleware  → req.agent
```

## Data model (full DDL)

```sql
-- Account: abstract entity, one per primary identity binding
CREATE TABLE agent_accounts (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  display_handle  TEXT,                  -- denormalized: 'github:shizhigu' or label
  tier            TEXT NOT NULL DEFAULT 'cold' CHECK (tier IN ('cold','warm','hot')),
  tier_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tier_change_reason TEXT,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
  suspended_at    TIMESTAMPTZ,
  closed_at       TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_accounts_status_active ON agent_accounts(status) WHERE status = 'active';

-- Identities: zero or more per account. UNIQUE on (provider, subject, audience).
CREATE TABLE agent_identities (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,                  -- 'github_app' | 'anthropic_attestation'
  subject             TEXT NOT NULL,                  -- durable upstream ID (GitHub numeric id)
  audience            TEXT NOT NULL,                  -- this SaaS's IdP client_id
  issuer              TEXT NOT NULL,                  -- 'github.com' / 'anthropic.com'
  assurance_level     TEXT NOT NULL CHECK (assurance_level IN ('low','medium','high')),
  display_handle      TEXT,
  is_primary          BOOLEAN NOT NULL DEFAULT false,
  status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
  revoked_at          TIMESTAMPTZ,
  revoked_reason      TEXT,
  revocation_source   TEXT,                           -- 'webhook'|'manual'|'expiry'|'cascade'
  verified_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_revalidated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata            JSONB,
  UNIQUE (provider, subject, audience)
);
-- Only one primary identity per account
CREATE UNIQUE INDEX agent_identities_one_primary ON agent_identities(account_id) WHERE is_primary AND status = 'active';
CREATE INDEX agent_identities_account_active ON agent_identities(account_id) WHERE status = 'active';

-- API keys: zero or more per account
CREATE TABLE agent_api_keys (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id               UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  issued_via_identity_id   UUID NOT NULL REFERENCES agent_identities(id),
  key_id                   TEXT NOT NULL UNIQUE,            -- public, e.g. 'agk_aB1cD2e'
  key_hash                 BYTEA NOT NULL,                  -- Argon2id of secret
  prefix                   TEXT NOT NULL,                   -- secret[:8] for display
  label                    TEXT,                            -- 'claude-code-laptop'
  scopes                   TEXT[] NOT NULL DEFAULT '{}',
  version                  INT NOT NULL DEFAULT 1,
  expires_at               TIMESTAMPTZ,
  last_used_at             TIMESTAMPTZ,
  rotation_state           TEXT NOT NULL DEFAULT 'active'
                            CHECK (rotation_state IN ('active','rotating','rotated','revoked')),
  rotated_at               TIMESTAMPTZ,
  rotation_grace_expires_at TIMESTAMPTZ,
  replaced_by_key_id       UUID REFERENCES agent_api_keys(id),  -- new key replacing this one
  created_by_key_id        UUID REFERENCES agent_api_keys(id),  -- if created via rotate-key
  revoked_at               TIMESTAMPTZ,
  revoked_reason           TEXT,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Active keys for fast lookup
CREATE INDEX agent_api_keys_active ON agent_api_keys(key_id) WHERE rotation_state IN ('active','rotating');
-- Each key can only be replaced ONCE
CREATE UNIQUE INDEX agent_api_keys_one_successor ON agent_api_keys(replaced_by_key_id) WHERE replaced_by_key_id IS NOT NULL;
CREATE INDEX agent_api_keys_account ON agent_api_keys(account_id);

-- Registration sessions: ties OAuth flow to poll_token
CREATE TABLE agent_registration_sessions (
  poll_token        TEXT PRIMARY KEY,                       -- random 256-bit, base64url
  nonce             TEXT NOT NULL UNIQUE,                   -- state= param sent to GitHub
  pkce_verifier     TEXT NOT NULL,                          -- random, never sent to client
  pkce_challenge    TEXT NOT NULL,                          -- S256 of verifier, sent in OAuth URL
  audience          TEXT NOT NULL,                          -- this SaaS's IdP client_id
  expected_provider TEXT NOT NULL,                          -- 'github_app'
  redirect_uri      TEXT NOT NULL,                          -- exact match for OAuth
  status            TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','exchanging','ready','consumed','failed','expired')),
  status_message    TEXT,
  result_ciphertext BYTEA,                                  -- encrypted JSON {key_secret, account_id, key_id, scopes, tier}; cleared on consume
  result_iv         BYTEA,                                  -- AES-GCM IV
  account_id        UUID REFERENCES agent_accounts(id),     -- set after exchange success
  expires_at        TIMESTAMPTZ NOT NULL,                   -- now() + 5 min
  consumed_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_reg_sessions_expires ON agent_registration_sessions(expires_at) WHERE status IN ('pending','ready');

-- Audit log: partitioned by day (lib creates partitions on init + cron)
CREATE TABLE agent_audit_log (
  id           BIGSERIAL,
  ts           TIMESTAMPTZ NOT NULL,
  account_id   UUID,
  key_id       TEXT,
  identity_id  UUID,
  event_type   TEXT NOT NULL,                  -- enum, see Events table below
  endpoint     TEXT,
  ip_hash      BYTEA,                          -- HMAC-SHA256(ip, server_secret)
  asn          INT,
  user_agent   TEXT,
  status_class INT,                            -- 2/3/4/5
  cost_units   INT NOT NULL DEFAULT 1,
  meta         JSONB,                          -- NEVER raw bodies/secrets/tokens
  PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);
-- Partitions created automatically (see operations section)
CREATE INDEX agent_audit_account_ts ON agent_audit_log USING BRIN (account_id, ts);
CREATE INDEX agent_audit_key_ts ON agent_audit_log USING BRIN (key_id, ts);
CREATE INDEX agent_audit_event_ts ON agent_audit_log USING BRIN (event_type, ts);

-- Webhook events (deduplication)
CREATE TABLE agent_webhook_events (
  id           UUID PRIMARY KEY,                -- upstream event ID for dedup
  provider     TEXT NOT NULL,
  event_type   TEXT NOT NULL,
  payload_hash BYTEA NOT NULL,                  -- SHA-256 of body
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ,
  status       TEXT NOT NULL DEFAULT 'received' CHECK (status IN ('received','processed','failed','ignored')),
  error        TEXT
);
CREATE INDEX agent_webhook_events_unprocessed ON agent_webhook_events(received_at) WHERE status = 'received';
```

## Identity provider interface (v3)

```ts
// Generic types

interface AttestationContext {
  audience: string                    // this SaaS's IdP client_id
  nonce: string                       // session nonce, also OAuth state=
  poll_token: string                  // for callback to bind to session
  ip_hash: Buffer
  user_agent: string
  redirect_uri: string                // exact match for OAuth
  pkce_challenge: string              // S256
  pkce_challenge_method: 'S256'
}

interface Attestation {
  issuer: string                      // 'github.com'
  subject: string                     // durable numeric ID
  audience: string                    // must match context.audience
  expires_at?: Date                   // for short-lived attestations
  display_handle?: string             // mutable handle for UX
  assurance_level: 'low' | 'medium' | 'high'
  supports_revalidation: boolean
  raw_metadata?: Record<string, unknown>
}

// Provider lifecycle

interface IdentityProvider {
  name: string                        // 'github_app' | 'anthropic_attestation'

  // Phase 1: kick off out-of-band proof gathering
  beginRegistration(ctx: AttestationContext): Promise<{
    challenge_url?: string            // browser URL for OAuth redirect
    deep_link?: string                // iOS/Android deep link
    device_code_info?: {              // OAuth device flow
      user_code: string
      verification_uri: string
      verification_uri_complete?: string
      expires_in_seconds: number
      poll_interval_seconds: number
    }
  }>

  // Phase 2: exchange code (OAuth) or verify proof (attestation/key)
  // For OAuth: called by lib's internal /callback/:provider handler
  // For non-redirect (attestation/api_key): called from /register
  exchangeOrVerify(input: ProviderInput, ctx: AttestationContext): Promise<Attestation>

  // Phase 3: optional revalidation (for tier upgrades, periodic checks)
  revalidate(identity: { provider: string, subject: string, audience: string }):
    Promise<{ still_valid: boolean, new_assurance_level?: Attestation['assurance_level'] }>

  // Phase 4: webhook handler (optional)
  handleWebhook?(headers: Record<string, string>, raw_body: Buffer):
    Promise<{ event_type: string, action: WebhookAction[] }>
}

type ProviderInput =
  | { kind: 'oauth_code', code: string, redirect_uri: string, pkce_verifier: string }
  | { kind: 'attestation_jwt', token: string }
  | { kind: 'api_key', key: string }
  | { kind: 'device_code', device_code: string }

type WebhookAction =
  | { type: 'revoke_identity', subject: string, reason: string }
  | { type: 'flag_identity', subject: string, signal: string }
```

## GitHub App provider (default, primary)

```ts
githubApp({
  client_id: 'Iv1.abcdef',           // from GitHub App settings (NOT app_id)
  client_secret: env.GH_CLIENT_SECRET,
  webhook_secret: env.GH_WEBHOOK_SECRET,  // for HMAC verification
  redirect_uri: 'https://saas.com/api/agent-auth/callback/github_app',
  default_assurance: 'medium',
  use_device_flow: false             // set true for headless agents (no browser)
})
```

### Browser-based OAuth flow (default)

```
[1] Agent → POST /api/agent-auth/begin-registration { provider: 'github_app' }
     Lib generates:
       - poll_token (256-bit random)
       - nonce (256-bit random) used as OAuth state=
       - pkce_verifier (256-bit random), pkce_challenge = base64url(sha256(verifier))
       - inserts agent_registration_sessions row, status='pending', expires_at=now()+5min
     Lib calls provider.beginRegistration(ctx):
       - Returns challenge_url:
         https://github.com/login/oauth/authorize?
           client_id=Iv1.abcdef
           &redirect_uri=https://saas.com/.../callback/github_app
           &state=<nonce>
           &code_challenge=<pkce_challenge>
           &code_challenge_method=S256
           &response_type=code
     Response: { poll_token, challenge_url, expires_at }

[2] Agent opens challenge_url (in user's browser, via OS-level open or display URL).
    User authorizes the GitHub App for THIS SaaS.

[3] GitHub redirects browser to:
     https://saas.com/api/agent-auth/callback/github_app?code=...&state=<nonce>

[4] Lib's GET /callback/:provider handler:
     a. SELECT agent_registration_sessions WHERE nonce = state AND status='pending' FOR UPDATE
        - If not found / expired: render 400 error page (do NOT leak which case)
     b. UPDATE status='exchanging'
     c. provider.exchangeOrVerify({
          kind: 'oauth_code', code, redirect_uri, pkce_verifier: row.pkce_verifier
        }, ctx)
        - GitHub POST /login/oauth/access_token with:
          client_id, client_secret, code, redirect_uri, code_verifier
        - Lib gets {access_token, ...}, calls GitHub /user
        - Audience is implicit: GitHub issued the code for our client_id;
          successful exchange with our client_secret confirms binding.
        - Returns Attestation { issuer: 'github.com', subject: <numeric_id>,
          audience: client_id, display_handle: login, assurance_level: 'medium' }
        - Token is DISCARDED. Lib only stores attestation.subject.
     d. Lib creates account + identity (UPSERT on (provider, subject, audience)):
        - If new: create agent_account, then agent_identity (is_primary=true)
        - If exists with status='active': fetch existing account_id, do NOT re-register
        - If exists with status='revoked': re-activate (UPDATE status='active', clear revoked_at)
     e. Lib creates new key:
        - Generate key_id (random 8 chars, prefixed 'agk_'), key_secret (random 256-bit)
        - key_hash = Argon2id(key_secret, salt=key_id, params: m=64MB,t=3,p=4)
        - INSERT agent_api_keys (issued_via_identity_id=identity.id, ...)
     f. Lib encrypts {key_secret, key_id, account_id, scopes, tier} as JSON,
        stores in result_ciphertext (AES-256-GCM, key derived from internal_secret + poll_token)
     g. UPDATE status='ready', account_id=...
     h. Render success page in browser: "You can return to your agent. Registration complete."

[5] Agent (polling): POST /api/agent-auth/registration-status { poll_token }
     a. SELECT row WHERE poll_token = ? AND expires_at > now() FOR UPDATE
        - Not found / expired: 410 { error: 'session_expired' }
     b. If status='pending' or 'exchanging': return 200 { status: 'pending' }
     c. If status='ready':
        - Decrypt result_ciphertext
        - UPDATE status='consumed', consumed_at=now(), result_ciphertext=NULL
        - Return 200 { status: 'completed', account_id, key: { key_id, secret, prefix, scopes, tier } }
     d. If status='consumed':
        - Return 410 { error: 'already_consumed' }
        - (Agent should have stored secret on first retrieval. Forces them to re-register if they didn't.)
     e. If status='failed': return 200 { status: 'failed', message }
```

**Key security properties:**

- Lib NEVER receives raw GitHub tokens. Only auth codes, server-side exchanged.
- Audience binding: GitHub issued code for OUR client_id; only OUR client_secret can exchange. Cross-SaaS replay impossible because other SaaS uses different client_id.
- Browser callback contains NO secret. The poll_token is in agent's hands, browser never sees agent's API key.
- Idempotency: if registration-status response is lost in transit, agent retries. Single retrieval clears the secret. After clear, agent must re-run begin-registration.
- TOCTOU: nonce lookup uses `SELECT FOR UPDATE`, atomic state transitions.

### Device flow (alternative for headless agents)

GitHub Apps support OAuth device flow. Use when agent has no browser:

```
[1] begin-registration with provider opts { use_device_flow: true }
     Returns { poll_token, device_code_info: {user_code, verification_uri, expires_in, poll_interval} }
[2] Agent shows user: "Visit https://github.com/login/device, enter code: WDJB-MJHT"
[3] User completes flow in any browser (their phone, etc.)
[4] Agent polls registration-status. Lib internally polls GitHub's token endpoint with device_code.
[5] On success, same flow as browser path.
```

### GitHub webhook handling

Subscribe GitHub App to `github_app_authorization` event (fired when user revokes app access).

```
POST /api/agent-auth/webhooks/github_app
  Headers: X-Hub-Signature-256, X-GitHub-Event, X-GitHub-Delivery (idempotency key)
  Body: GitHub event JSON

Lib:
  1. INSERT agent_webhook_events ON CONFLICT(id) DO NOTHING — dedup
  2. Verify HMAC-SHA256(body, webhook_secret) matches signature header (constant time)
  3. If event = github_app_authorization, action = revoked:
     a. Find agent_identity WHERE provider='github_app' AND subject=<sender.id>::text AND audience=<our client_id>
     b. UPDATE status='revoked', revoked_at=now(), revoked_reason='user_revoked_app_access', revocation_source='webhook'
     c. Cascade: UPDATE agent_api_keys SET revoked_at=now(), revoked_reason='primary_identity_revoked'
        WHERE issued_via_identity_id=<identity.id> AND revoked_at IS NULL
     d. UPDATE agent_accounts SET status='suspended' if no other active primary identity
     e. Publish to Redis pub/sub: 'agent-auth:invalidate:account:<id>' for cache eviction
  4. UPDATE agent_webhook_events SET status='processed'
```

## Account / Identity / Key state machines

### Account states
```
active ──suspend──> suspended ──unsuspend──> active
   │                    │
   └─────close──────────┴──────────> closed (terminal)
```

### Identity states
```
active ──revoke (webhook|manual|expiry)──> revoked
                                                │
                                            (terminal until re-verify creates new identity row)
```

### Key states (rotation_state)
```
active ──/rotate-key──> rotating ──grace expires──> rotated (terminal)
   │                       │
   │                       └──/revoke (emergency)──> revoked
   └──/revoke──────────────────────────────────────> revoked (terminal)
```

State transitions are atomic via row-level locks. No state may be skipped.

## API contracts (full)

### POST /begin-registration

```
Request:
  Content-Type: application/json
  { "provider": "github_app",
    "use_device_flow": false,             // optional
    "label": "claude-code-laptop"         // optional, attached to issued key
  }

Response 200:
  { "poll_token": "<256-bit base64url>",
    "challenge_url": "https://github.com/login/oauth/authorize?...",   // browser flow
    "device_code_info": null,                                           // or filled if device flow
    "expires_at": "2026-04-30T12:05:00Z",
    "poll_interval_seconds": 2
  }

Errors:
  400 invalid_provider
  400 invalid_label
  429 too_many_registrations (per-IP)
  500 internal_error
```

### POST /registration-status

```
Request: { "poll_token": "..." }

Response 200 (pending):  { "status": "pending" }
Response 200 (completed):
  { "status": "completed",
    "account_id": "uuid",
    "key": {
      "key_id": "agk_aB1cD2e",
      "secret": "<full key, shown only once>",
      "prefix": "abcdefgh",
      "scopes": ["read"],
      "tier": "cold",
      "label": "claude-code-laptop"
    }
  }
Response 200 (failed): { "status": "failed", "code": "user_denied|...", "message": "..." }
Response 410: { "error": "session_expired" | "already_consumed" }
```

### POST /issue-key

Issues additional API key for an EXISTING account. Requires fresh OAuth proof.

```
Request: { "poll_token": "<from a fresh begin-registration that completed>",
           "label": "cursor-desktop" }

Response 200:
  { "key": { "key_id": "...", "secret": "...", "prefix": "...", "scopes": [...], "tier": "..." } }

Errors:
  401 invalid_poll_token
  409 account_mismatch  (the verified identity doesn't match an existing account, or
                          ambiguous: multiple accounts share this identity)
  410 session_expired
```

Note: This re-uses the begin-registration → callback → poll flow. Lib detects in step [4d] above that account exists, sets a flag in encrypted result that this is "additional key" not "first key". Agent calls /issue-key with poll_token.

Actually simpler: /registration-status always returns the key. The semantic difference (first key vs additional) is just an `is_first` field on the response. /issue-key endpoint is unnecessary — registration flow is the same.

**Revised:** /issue-key is REMOVED. Agent uses normal /begin-registration → /registration-status flow. Response includes `is_first_key: bool`.

### POST /rotate-key

Rotate an existing API key. Old key remains valid during grace.

```
Request:
  Authorization: Bearer <existing_key>
  { "grace_seconds": 3600,         // 0 = emergency rotation, no grace
    "reason": "scheduled_rotation" }

Response 200:
  { "old_key": { "key_id": "...", "rotated_at": "...", "grace_expires_at": "..." },
    "new_key": { "key_id": "...", "secret": "...", "prefix": "...", "scopes": [...] } }

Concurrency: SELECT old_key FOR UPDATE; verify rotation_state = 'active'; create new key
            with created_by_key_id = old.id; UPDATE old.rotation_state = 'rotating',
            rotated_at = now(), grace_expires_at = now() + grace_seconds,
            replaced_by_key_id = new.id. All in single transaction.

Errors:
  401 invalid_key
  409 already_rotating (concurrent rotate detected)
  403 insufficient_scopes (key lacks 'self:rotate')
```

A background job (or middleware on next access of old key) transitions
rotating → rotated when grace expires.

### POST /revoke

```
Request:
  Authorization: Bearer <key>  OR  signed admin request
  { "key_id": "...",                     // self-revoke or admin-revoke
    "reason": "lost_device" }

Response 200: { "revoked_at": "..." }

Behavior:
  - Self-revoke: key in Authorization must be the one being revoked, or have 'admin:keys' scope
  - Lib publishes 'agent-auth:invalidate:key:<key_id>' to Redis pubsub
  - Cache eviction within 30s worst case (TTL); pubsub for best-effort immediate
```

### POST /recover-account

Owner-gated. For lost keys.

```
Request:
  { "poll_token": "<from a fresh OAuth flow that proved identity ownership>" }

Behavior:
  - Verify identity from poll_token matches an existing account
  - Mark all account's keys revoked (rotation_state='revoked', reason='account_recovery')
  - Issue new key
  - Notify SaaS owner via configured webhook

Response 200: { "account_id": "...", "key": {...}, "revoked_count": N }

Configuration:
  recover_account: {
    require_owner_approval: true,        // default
    approval_webhook_url: 'https://saas.com/internal/agent-auth/approve-recovery',
    approval_timeout_seconds: 86400      // 24h
  }
```

If require_owner_approval=true: lib POSTs to approval_webhook with details. SaaS owner's
endpoint must POST back to /recover-account-confirm within timeout. This is the SaaS owner's
chance to verify out-of-band (email user, manual review).

### GET /keys

```
Request: Authorization: Bearer <key_with_admin:keys_scope>

Response 200:
  { "keys": [
      { "key_id": "...", "prefix": "...", "label": "...", "scopes": [...],
        "tier": "...", "rotation_state": "...", "created_at": "...", "last_used_at": "..." }
    ]
  }
```

### GET /.well-known/agent-auth

```
Response 200:
  { "version": "v3",
    "endpoints": {
      "begin_registration": "https://saas.com/api/agent-auth/begin-registration",
      "registration_status": "https://saas.com/api/agent-auth/registration-status",
      "rotate_key": "https://saas.com/api/agent-auth/rotate-key",
      "revoke": "https://saas.com/api/agent-auth/revoke",
      "recover_account": "https://saas.com/api/agent-auth/recover-account"
    },
    "supported_providers": [
      { "name": "github_app", "supports_browser_flow": true, "supports_device_flow": true,
        "default_assurance": "medium" }
    ],
    "available_scopes": ["read", "write", "admin:keys", "self:rotate"],
    "rate_limit_headers": {
      "remaining": "X-RateLimit-Remaining",
      "reset": "X-RateLimit-Reset",
      "limit": "X-RateLimit-Limit"
    },
    "documentation_url": "https://saas.com/docs/agent-auth",
    "registration_max_age_seconds": 300,
    "min_revocation_latency_seconds": 30
  }
```

## Key validation middleware

```
On every request to /api/agent/v1/*:
  1. Extract Authorization: Bearer <key>
  2. Parse: regex /^agk_([a-zA-Z0-9]+)_(.+)$/ → key_id, secret
  3. Cache lookup: Redis key 'agent-auth:key:<key_id>' (TTL 30s)
     - If hit: use cached {account_id, key_hash, scopes, tier, rotation_state, version}
     - If miss: SELECT FROM agent_api_keys WHERE key_id = ?
       - If no row: 401
       - Cache result with TTL=30s
  4. Constant-time Argon2id verify(secret, cached.key_hash)
     - Mismatch: 401
  5. Check rotation_state:
     - 'active': proceed
     - 'rotating': proceed (grace period)
     - 'rotated' or 'revoked': 401, with helpful header X-Agent-Auth-Reason
  6. Check expires_at < now(): 401 expired
  7. Per-key + per-account + per-route rate limit check (see rate limit section)
  8. UPDATE last_used_at (async, fire-and-forget)
  9. Set req.agent = AgentContext{...}
  10. next()

Cache invalidation:
  - 30s TTL is hard floor (worst-case revocation latency)
  - Redis pubsub 'agent-auth:invalidate:key:<id>' fires on revoke/rotate-emergency
  - Subscribers (each app process) evict from local cache
  - This is best-effort; TTL is the guarantee
```

## Rate limiting

### Algorithm: GCRA (Generic Cell Rate Algorithm)

Single Lua script, atomic per Redis key. Multi-key (multi-dimensional) limiting is
NOT atomic across dimensions in v0.1; we accept this with explicit ordering:

1. Per-key (most specific, hardest to game)
2. Per-account
3. Per-route + cost_units
4. Per-IP (registration only)
5. Global emergency brake

If any check fails, request fails. Order matters to keep the per-key counter clean.

```lua
-- gcra.lua
-- KEYS[1] = bucket key
-- ARGV[1] = period_seconds (rate)
-- ARGV[2] = burst_capacity
-- ARGV[3] = cost_units (default 1)
-- Returns: { allowed: 0|1, remaining: int, reset_after: float }

local key = KEYS[1]
local period = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost = tonumber(ARGV[3] or 1)
local rate = burst / period   -- units/second

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1e6

local last_state = redis.call('GET', key)
local tat = last_state and tonumber(last_state) or now

local interval = cost / rate
local new_tat = math.max(tat, now) + interval
local delay = new_tat - now

if delay > burst / rate then
  -- rejected
  return { 0, 0, math.ceil((tat - now) * 1000) }
end

local ttl = math.ceil((new_tat - now) + period)
redis.call('SET', key, new_tat, 'EX', ttl)

local remaining = math.floor((burst - delay * rate))
return { 1, remaining, math.ceil((new_tat - now) * 1000) }
```

### Configuration (v0.1 defaults)

```ts
rate_limit: {
  per_key:    { burst: 100,   per: '1m' },   // 100 req/min, burst-tolerant
  per_account: { burst: 5000, per: '1d' },   // sums across keys
  per_route_overrides: {
    'POST /api/agent/v1/expensive': { cost_units: 10 }
  },
  per_ip_registration: { burst: 5, per: '1h' },  // registrations from same IP
  global_emergency: { burst: 1000000, per: '1h' }
}
```

### Non-atomic dimensions (documented)

If global cap exhausted but per-key passes, the request still passes per-key.
Operators must monitor for distributed limit breaches separately. This is acceptable
because: (a) global is emergency brake, not primary defense; (b) per-key is the
actual abuse vector; (c) atomicity across hash slots is a Redis cluster constraint.

## Spam / abuse model

Sybil defense relies on **upstream identity cost**, NOT on time-based promotion:

- Cold tier: any verified medium-assurance identity. 100 req/min, 5000 req/day.
- Warm tier: cold + 14 days clean tenure + risk_score < 0.4. Default same limits, but
  unlocks SaaS-defined "warm-only" scopes (SaaS owner decides).
- Hot tier: SaaS owner manual or webhook promotion. Library does not auto-promote.

**Risk scoring (signals, not enforcement):**
```ts
type RiskSignal =
  | { kind: 'identity_assurance', value: 'low'|'medium'|'high', weight: 0.4 }
  | { kind: 'tenure_days', value: number, weight: 0.1 }
  | { kind: 'success_rate_30d', value: 0..1, weight: 0.1 }
  | { kind: 'cost_volatility', value: number, weight: 0.05 }
  | { kind: 'asn_diversity_24h', value: number, weight: 0.1 }
  | { kind: 'ip_reputation', value: 0..1, weight: 0.15 }
  | { kind: 'manual_owner_flag', value: 'trusted'|'suspicious'|null, weight: 0.5 }

risk_score = clip(0, 1, sum(weight * normalize(signal)))
```

**Explicit acknowledgment of farming attack:**
- Cheapest farm: aged GitHub accounts (~$5 each on grey markets) + clean residential IPs +
  smooth behavior + 14 days wait → warm-tier promotion possible.
- Mitigation: warm tier MUST NOT unlock expensive operations by default.
- SaaS owner is responsible for setting hot-tier promotion criteria (Stripe charge,
  ID verification, manual review). Lib provides hooks, not policy.
- For high-value SaaS: configure `require_high_assurance_identity: true` to require
  Anthropic-signed attestation (when available) for hot tier.

## Confused deputy prevention

```ts
interface AgentContext {
  account_id: string
  key_id: string
  identity: {
    provider: string
    subject: string
    display_handle?: string
    assurance_level: 'low' | 'medium' | 'high'
  }
  scopes: ReadonlySet<string>
  tier: 'cold' | 'warm' | 'hot'
  has_scope(scope: string): boolean
  require_scope(scope: string): void   // throws AgentAuthError 403 if missing
}

// Type augmentation for Express/Hono:
declare module 'express' {
  interface Request {
    agent?: AgentContext
    // NOTE: req.user is intentionally NOT extended. Agent and human contexts are disjoint.
  }
}
```

Lint rule (shipped with lib): warn if `req.user` is read from a route protected by
`agents.middleware`. Encourage explicit `req.agent`.

## DX

```ts
import { agentAuth, githubApp } from 'agent-auth'
import { postgresAdapter, redisAdapter } from 'agent-auth/adapters'

const agents = agentAuth({
  internal_secret: env.AGENT_AUTH_SECRET,         // required, 256-bit
  identity_providers: [
    githubApp({
      client_id: env.GH_CLIENT_ID,
      client_secret: env.GH_CLIENT_SECRET,
      webhook_secret: env.GH_WEBHOOK_SECRET,
      redirect_uri: 'https://saas.com/api/agent-auth/callback/github_app'
    })
  ],
  storage: postgresAdapter({ connection_string: env.DATABASE_URL }),
  cache: redisAdapter({ url: env.REDIS_URL }),
  rate_limit: { /* defaults */ },
  audit_log: { retention_days: 90 },
  recover_account: { require_owner_approval: true, approval_webhook_url: '...' }
})

app.use('/api/agent-auth', agents.routes())
app.use('/api/agent/v1', agents.middleware, myAgentRoutes)
```

## Local testing harness

```ts
import { agentAuth, mockProvider, inMemoryStorage, fakeClock } from 'agent-auth/testing'

const clock = fakeClock(new Date('2026-01-01'))
const agents = agentAuth({
  internal_secret: 'test',
  identity_providers: [mockProvider({
    name: 'github_app',
    auto_approve: true,
    next_subject: () => 'fake-user-' + Math.random()
  })],
  storage: inMemoryStorage(),
  clock
})

// Tests
const reg = await agents.test.register({ provider: 'github_app', subject: '12345' })
expect(reg.is_first_key).toBe(true)
expect(reg.tier).toBe('cold')

clock.advance(15 * 24 * 3600 * 1000)
await agents.test.simulate_calls(reg.key_id, { count: 800, success_rate: 0.95 })
const account = await agents.test.get_account(reg.account_id)
expect(account.tier).toBe('warm')

await agents.test.simulate_revocation_webhook({ provider: 'github_app', subject: '12345' })
const after = await agents.test.get_account(reg.account_id)
expect(after.status).toBe('suspended')
const key_check = await agents.test.validate_key(reg.key_id)
expect(key_check.valid).toBe(false)
```

## Threat model (concrete)

| Attacker | Capability | Mitigation |
|---|---|---|
| Steal user's GitHub OAuth code in browser | Could try to redeem with another SaaS | Code bound to OUR client_id; other SaaS lacks our client_secret |
| Steal poll_token | Could call /registration-status before agent | Agent gets 410 already_consumed; learns to re-register |
| Steal issued API key | Full agent access until revoke + 30s | Per-key revoke, leaked-prefix scanner (scan public GitHub for `agk_` prefixes), short cache TTL |
| Compromise lib (npm supply chain) | Could mint keys, log tokens | Sigstore signed releases, no telemetry by default, audit_log scrubbing rules |
| Compromise SaaS DB | Sees subjects, IP hashes, key hashes (Argon2id) | No plaintext keys/tokens, IP hashed with HMAC, audit log meta scrubbed |
| Replay /register | Same nonce already consumed | nonce single-use, unique constraint, atomic state transition |
| Replay /registration-status after consume | Returns 410 | result_ciphertext cleared on first retrieve |
| Race two /rotate-key | Could mint multiple successors | SELECT FOR UPDATE, unique index on replaced_by_key_id |
| Forge GitHub webhook | Trigger false revocation | HMAC-SHA256 verification with webhook_secret, constant-time compare |
| Replay GitHub webhook | Same revocation processed twice | UNIQUE on agent_webhook_events.id (X-GitHub-Delivery) |
| Time-based farming | Wait 14 days, get warm | Warm doesn't unlock expensive ops; SaaS owner gates hot tier |

## PII / data handling rules

- GitHub `display_handle` (login) stored, but understood mutable; subject (numeric ID) is durable.
- GitHub email NOT requested in OAuth scope by default. SaaS opts in via config.
- Audit log `meta` JSONB MUST NOT contain: API keys (full), upstream tokens, request bodies, response bodies, credit card data.
- IP addresses stored as HMAC-SHA256(ip, internal_secret), not plaintext. Cannot be reversed.
- Logs scrubbed with regex on `agk_*`, `gh_pat_*`, `ghp_*`, `sk-ant-*` patterns by default.
- Account deletion (`closed` state): keys revoked, identities revoked, account row retained
  with all PII fields nulled. audit_log retained per retention policy. Right-to-erasure
  endpoint available for full purge (SaaS owner responsibility).

## Operations

### Database migrations

Lib ships migration files in `migrations/`. SaaS runs `npx agent-auth migrate` (or programmatic equivalent). Each migration is idempotent and incremental.

### Audit log partitioning

Daily partitions, created automatically via cron task lib spawns:

```ts
agents.scheduled_jobs.start()  // creates daily partition + drops partitions > retention_days
```

Or: Postgres pg_partman extension if available. Lib detects and uses it.

### Webhook delivery & retries

GitHub retries webhooks up to 5 times with exponential backoff. Lib responds 2xx if event
was deduped or processed; 5xx triggers GitHub retry. 4xx (e.g. invalid signature) does not.

### Observability

Lib exposes Prometheus-compatible metrics via optional `agents.metrics()` middleware:

```
agent_auth_registrations_total{provider, outcome}
agent_auth_keys_active
agent_auth_keys_rotations_total{type}
agent_auth_keys_revocations_total{reason}
agent_auth_rate_limit_hits_total{dimension}
agent_auth_validation_latency_seconds (histogram)
agent_auth_webhook_events_total{provider, event_type, status}
```

OpenTelemetry tracing: spans on all public endpoints, propagated to identity provider calls.

## Migration / shadow mode

```ts
agents.shadow_mode({
  detect_existing_agent_traffic: (req) => req.headers['user-agent']?.includes('Claude'),
  log_what_would_happen: true,
  enforce: false
})
```

Run for 2-4 weeks. Lib emits log lines like:
```
[agent-auth shadow] Would have rate-limited request POST /api/v1/foo from key=existing_legacy_key
[agent-auth shadow] Would have allowed request from agent-auth-managed key=agk_...
```

Review, then flip enforce=true.

## Deliberate non-goals (v0.1)

- Payment integration (SaaS owner provides own promotion hook)
- Browser automation / agent-side SDKs (out of scope)
- Cross-SaaS portable identity (different problem)
- Inter-agent A2A communication (different problem)
- Agent governance / runtime policy (Microsoft AGT does this)
- Real-time observability dashboard UI (logs only)
- LLM-based abuse detection (signals are deterministic only)

## Scope explicitly compromised in v0.1 (with rationale)

| Compromise | Why | Recovery path |
|---|---|---|
| 30-second worst-case revocation latency | Pubsub is best-effort, TTL is the guarantee. Per-request DB version lookup adds 1 RTT to every API call. | Operators can set TTL=5s if latency-critical. v0.2 adds optional version-on-every-request mode. |
| Multi-dimensional rate limit not atomic across dimensions | Redis cluster hash slots prevent this. Atomic only same-slot. | Single Redis primary works fine for most scales. v0.2 adds reservation-based atomic multi-dim. |
| Risk score is heuristic, gameable by patient attacker | True Sybil resistance requires proof-of-payment or strong attestation, neither available universally yet. | Hot tier requires manual/webhook promotion; warm tier doesn't unlock expensive ops. |
| No automatic primary identity replacement | If user loses GitHub account, account is stuck. | /recover-account with owner approval covers this case. |
| Time-of-check-to-time-of-use on cached key validation | 30s window where revoked key still works. | Documented in /.well-known. SaaS owner can set TTL=0 if critical (with cost). |

## Round-3 audit questions for codex

1. Does the OAuth flow now correctly bind audience? Are there cross-SaaS replay paths still open?

2. Does the poll_token + result_ciphertext approach correctly solve the idempotency vs leakage tradeoff? Any TOCTOU between exchange completion and ciphertext write?

3. Is the rotation schema (rotation_state + replaced_by_key_id + UNIQUE index) sufficient to prevent the multi-successor race? Walk through the race scenario.

4. Does the cascade from identity revocation → key revocation work correctly? Edge case: identity is one of multiple primary identities (is that possible in v3 schema?). What if cascade fails halfway?

5. Is /recover-account's owner-webhook approval flow secure? What if the approval webhook is replayed? What if owner's approval endpoint is compromised?

6. Are there scope leak paths through the AgentContext interface? Could a SaaS handler accidentally promote scopes by mutating req.agent?

7. Is the GCRA Lua script correct under high concurrency? Are there overflow scenarios?

8. Is the webhook deduplication (X-GitHub-Delivery as PK) robust against attacker replays? What if attacker forges a valid signature on a stale event?

9. Is the audit log meta field safe? Are scrubbing rules complete? What if SaaS owner's app code passes secrets through agents.audit() helper?

10. Time-skew between lib and Redis (TIME command) and Postgres (now()) — any places where this could cause incorrect state transitions?

11. Anything I missed? Anything that's still "good enough but technically wrong"?

12. Honest grade: is this v3 spec at "minimum acceptable compromise" or are there findings that would push to v4?
