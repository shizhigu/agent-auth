# agent-auth v4 spec (post round-3 audit)

This is a focused patch over v3. Only documents the changes from v3. Reference v3 for unchanged content.

## Summary of v4 changes

| v3 issue | v4 fix |
|---|---|
| 1. Registration idempotency consumes secret too eagerly | Client-encrypted secret delivery via ephemeral keypair. No server-side replay window needed. |
| 2. UNIQUE index on `replaced_by_key_id` is wrong invariant | Switch to `UNIQUE (created_by_key_id) WHERE NOT NULL`. Keep both as separate constraints. |
| 3. Revoked keys still validate (middleware reads rotation_state only) | Add `rotation_state='revoked'` everywhere revoke fires. Middleware checks BOTH rotation_state AND revoked_at. Add CHECK constraint. |
| 4. Middleware doesn't check account/identity status | Validation cache joins account.status + identity.status. Cascade rules tightened. |
| 5. Rotating keys outlive grace | Middleware compares `now() < rotation_grace_expires_at` for rotating keys. Auto-transitions on access. |
| 6. Webhook order: dedup before HMAC | HMAC verify FIRST, dedup INSERT after. Mismatched payload_hash on duplicate delivery_id triggers alert. |
| 7. GitHub doesn't auto-retry webhooks | Reconciliation job: periodically poll GitHub user revocation list for app, reconcile with our identities. |
| 8. Identity state machine contradicts DDL | `revoked → active` only via fresh OAuth AND only for `revocation_source IN ('webhook','expiry')`. Manual revocations are terminal. |
| 9. Device flow storage missing | New `agent_device_flows` table for device_code / interval / slow_down. Encrypted device_code at rest. |
| 10. Key format inconsistency | Canonical: `agk_<public_id>_<secret_b64>`. `agent_api_keys.key_id = "agk_<public_id>"`. Regex updated. |

Plus minor:
- Remove /issue-key endpoint reference (use begin-registration flow with `is_first_key` response field)
- Fix /recover-account vs /registration-status semantics (recovery uses different poll_token namespace)
- Cache invalidation: pubsub publishes DEL command, all subscribers DEL their local + DEL Redis cache entry
- Add `tier` column to `agent_api_keys` (cached from account at issue time, refreshed on tier change)
- Default scopes include `self:rotate` for all issued keys
- Object.freeze(req.agent), scopes as frozen array + has_scope is closure over private set
- GCRA: validate inputs, fix reject reset_after to report time-until-next-allowed
- Audit meta: allow-listed schemas, max key depth, max byte size, recursive key-name redaction

---

## Detail: Finding 1 — Client-encrypted secret delivery

**v3 problem:** Once /registration-status returns the secret, ciphertext cleared. If response lost, retry returns 410 already_consumed. Secret gone.

**v4 fix:** Agent generates ephemeral X25519 keypair before /begin-registration. Sends pubkey. Server encrypts secret WITH AGENT'S PUBKEY before storing. Store-and-forward: ciphertext can be retrieved multiple times because only the agent (with private key) can decrypt.

```
[1] Agent generates ephemeral X25519 keypair (sk, pk).
[2] POST /begin-registration { provider, label, client_pubkey: base64(pk) }
[3] Lib stores client_pubkey in agent_registration_sessions.
[4] After OAuth + key issuance:
    - Lib encrypts {key_secret, key_id, ...} JSON with NaCl box (recipient = client_pubkey,
      sender = lib's ephemeral keypair derived from internal_secret + nonce).
    - Stores result_ciphertext + lib_pubkey + box_nonce.
    - Status = 'ready'. NO consumption yet.
[5] Agent polls /registration-status:
    - Returns { status: 'completed', encrypted_payload, lib_pubkey, box_nonce }
    - Idempotent: server does NOT clear payload on retrieve.
    - Agent decrypts locally with its sk + lib_pubkey.
[6] Cleanup: agent_registration_sessions.expires_at (5 min) drops payload.
```

Result: replay-safe, idempotent, no secret in plaintext ever stored on server, agent owns decryption key (lost only if agent crashes before getting payload).

**Storage change:**
```sql
ALTER TABLE agent_registration_sessions
  ADD COLUMN client_pubkey BYTEA,        -- agent's X25519 public key (32 bytes)
  ADD COLUMN lib_pubkey BYTEA,           -- lib's X25519 public key (32 bytes), per-session
  ADD COLUMN box_nonce BYTEA;            -- NaCl box nonce (24 bytes)
-- result_ciphertext stays, but is now NOT cleared on consume
-- result_iv removed (NaCl box uses box_nonce instead of separate IV)
ALTER TABLE agent_registration_sessions DROP COLUMN result_iv;
```

**State machine change:** `consumed` state removed. Sessions go pending → exchanging → ready → expired (TTL).

## Detail: Finding 2 — Rotation uniqueness

```sql
-- v3: WRONG (prevents two keys having same successor, not what we want)
-- CREATE UNIQUE INDEX agent_api_keys_one_successor ON agent_api_keys(replaced_by_key_id) WHERE replaced_by_key_id IS NOT NULL;

-- v4:
-- One key may only have ONE replacement (correct invariant)
CREATE UNIQUE INDEX agent_api_keys_one_predecessor ON agent_api_keys(created_by_key_id) WHERE created_by_key_id IS NOT NULL;
-- And: a successor key has exactly one predecessor (already enforced by created_by_key_id being a single value)
-- Keep replaced_by_key_id for forward-traversal denormalization, but no UNIQUE on it
```

Rationale: `created_by_key_id` is the FK on the NEW key pointing back to OLD key. UNIQUE on this column means "no two new keys claim the same old key as creator", which prevents multi-successor.

## Detail: Finding 3 — Revoked keys validation

**v3 problem:** revoke cascade only updates `revoked_at`, middleware reads `rotation_state`. So `rotation_state='active'` + `revoked_at NOT NULL` passes.

**v4 fix:**

```sql
-- 1. Add CHECK constraint: revoked_at NOT NULL implies rotation_state='revoked'
ALTER TABLE agent_api_keys
  ADD CONSTRAINT agent_api_keys_revoked_state_consistent
  CHECK ((revoked_at IS NULL) = (rotation_state != 'revoked'));

-- 2. All revoke paths set BOTH:
UPDATE agent_api_keys
SET rotation_state = 'revoked',
    revoked_at = now(),
    revoked_reason = ?
WHERE id = ?;
```

**Middleware update:**
```
... rotation_state check:
- 'active': proceed (also assert revoked_at IS NULL via CHECK)
- 'rotating': check now() < rotation_grace_expires_at; if expired, reject (transition handled below)
- 'rotated': reject 401, header X-Agent-Auth-Reason: 'key_rotated'
- 'revoked': reject 401, header X-Agent-Auth-Reason: 'key_revoked'

Auto-transition on access (best-effort, async):
If rotation_state = 'rotating' AND now() >= rotation_grace_expires_at:
  enqueue background task: UPDATE rotation_state = 'rotated' WHERE ... AND rotation_state = 'rotating'
  reject this request (don't serve with expired grace)
```

## Detail: Finding 4 — Account/identity status check in middleware

```
Middleware now caches:
  cache_key = 'agent-auth:key:<key_id>'
  cache_value = {
    account_id, account_status, key_hash, scopes, tier, rotation_state, revoked_at,
    grace_expires_at, primary_identity_id, primary_identity_status, version
  }
  TTL = 30s

Validation:
  - Key exists, not expired (rotation_state, revoked_at, grace, expires_at)
  - account_status = 'active' (suspended/closed → 401 with reason)
  - primary_identity_status = 'active' (revoked → 401)

Cascade on account suspension:
  UPDATE agent_api_keys SET rotation_state='revoked', revoked_at=now(),
    revoked_reason='account_suspended'
  WHERE account_id = ? AND rotation_state IN ('active','rotating');

  Pubsub: 'agent-auth:invalidate:account:<id>' → all subscribers DEL all keys for this account
```

## Detail: Finding 5 — Grace expiry enforcement

Already covered in Finding 3 update. Explicit:

```
On every request to /api/agent/v1/*:
  if cached.rotation_state == 'rotating':
    if now() >= cached.grace_expires_at:
      enqueue async transition (rotating → rotated)
      reject 401, header X-Agent-Auth-Reason: 'rotation_grace_expired'
```

Background job (every 60s):
```sql
UPDATE agent_api_keys
SET rotation_state = 'rotated'
WHERE rotation_state = 'rotating' AND rotation_grace_expires_at < now();
```

## Detail: Finding 6 — Webhook ordering

**v3 (wrong):**
```
1. INSERT agent_webhook_events ON CONFLICT DO NOTHING
2. Verify HMAC
```

**v4 (correct):**
```
1. Read raw body (preserve bytes for HMAC)
2. Verify HMAC-SHA256(body, webhook_secret) == X-Hub-Signature-256 (constant time)
   - If fail: 401, drop, do NOT log content
3. Parse body to get event ID (X-GitHub-Delivery header)
4. INSERT INTO agent_webhook_events (id, payload_hash, ...)
   ON CONFLICT (id) DO UPDATE SET ... RETURNING (xmax = 0) AS inserted
   - If inserted=true: process
   - If inserted=false (duplicate):
     SELECT payload_hash from existing row
     IF existing.payload_hash != new.payload_hash:
       LOG ALERT: webhook_id_collision (possible attack or upstream bug)
     RETURN 200 (already processed)
5. Process event
6. UPDATE agent_webhook_events SET status='processed', processed_at=now()
7. RETURN 200
```

Atomic property: signature verified before any DB write. Duplicate detection AFTER signature verification.

## Detail: Finding 7 — GitHub doesn't auto-retry; reconciliation job

**v4 addition:**

```ts
// Background job runs hourly
async function reconcileGithubAuthorizations() {
  // For each active GitHub-issued identity, check if app authorization still valid.
  // GitHub API: GET /user/installations + each installation's authorized users.
  // No direct "list of who authorized this app" endpoint, so we use a different
  // approach:
  //   1. We track last_revalidated_at per identity.
  //   2. When > 24h, lib calls GitHub /user with stored... wait, we don't store tokens.
  //
  // Real approach:
  //   - Use the `installation` access token of the GitHub App.
  //   - GitHub API: GET /app/installations returns all install IDs.
  //   - For each, GET /user/installations/{installation_id}/repositories with installation token.
  //   - This doesn't directly tell us about user authorizations though.
  //
  // What we actually do:
  //   - On each user's next /api/agent/v1/* request after 24h since last_revalidated_at,
  //     enqueue an async re-verify task.
  //   - Re-verify task uses app's JWT to call GitHub on behalf of installation, checks
  //     app authorization for that user is still valid.
  //   - If GitHub reports user revoked, mark identity revoked + cascade.
  //   - Pure passive: only checks active users; revoked-but-no-traffic users self-cleanup
  //     when they try to use API.
}
```

This is acknowledged as imperfect: revoked identities with no traffic stay 'active' in our DB until their first post-revocation request. Acceptable because: (a) those users aren't using the keys, so no impact; (b) on first use, we re-verify and revoke.

For SaaS owners with stricter requirements, optional explicit polling job can be enabled via config.

## Detail: Finding 8 — Identity state machine

**v4 corrected state machine:**

```
active ─revoke(webhook)──> revoked(webhook)  ──fresh-OAuth──> active
       ─revoke(expiry)───> revoked(expiry)   ──fresh-OAuth──> active
       ─revoke(manual)──> revoked(manual)   [TERMINAL — no re-activation]
       ─revoke(cascade)─> revoked(cascade)  [TERMINAL]
```

In code:
```sql
-- During registration: check if existing identity can be re-activated
SELECT * FROM agent_identities
WHERE provider = ? AND subject = ? AND audience = ?
FOR UPDATE;

IF row found:
  IF status = 'active': re-use (no new identity row)
  IF status = 'revoked' AND revocation_source IN ('webhook', 'expiry'):
    UPDATE status = 'active', revoked_at = NULL, revoked_reason = NULL,
           revocation_source = NULL, last_revalidated_at = now()
    -- old key revocations stay revoked; user gets new key
  IF status = 'revoked' AND revocation_source IN ('manual', 'cascade'):
    REJECT registration (409 identity_blocked)
    -- SaaS owner must manually unblock via admin endpoint if mistaken
ELSE:
  INSERT new identity row
```

## Detail: Finding 9 — Device flow storage

```sql
CREATE TABLE agent_device_flows (
  device_code_hash    BYTEA PRIMARY KEY,           -- SHA-256 of GitHub device_code
  device_code_encrypted BYTEA NOT NULL,            -- AES-GCM encrypted device_code
  device_code_iv      BYTEA NOT NULL,
  user_code           TEXT NOT NULL,               -- shown to user
  verification_uri    TEXT NOT NULL,
  expires_at          TIMESTAMPTZ NOT NULL,
  poll_interval_seconds INT NOT NULL DEFAULT 5,
  next_poll_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  poll_token          TEXT NOT NULL UNIQUE REFERENCES agent_registration_sessions(poll_token),
  status              TEXT NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','authorized','denied','expired','slow_down')),
  attempts            INT NOT NULL DEFAULT 0,
  last_error          TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX agent_device_flows_active ON agent_device_flows(next_poll_at, status) WHERE status = 'pending';
```

Background job polls `next_poll_at <= now() AND status='pending'`:
- Decrypts device_code
- Calls GitHub /login/oauth/access_token with grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code, client_id
- On 'authorization_pending': UPDATE next_poll_at = now() + poll_interval_seconds
- On 'slow_down': UPDATE poll_interval_seconds = poll_interval_seconds + 5
- On 'expired_token': UPDATE status='expired', mark session 'failed'
- On success: complete OAuth flow (same path as browser callback)

## Detail: Finding 10 — Canonical key format

```
Canonical format: agk_<public_id>_<secret_b64>
  - public_id: 8 chars from URL-safe base64 (~48 bits entropy)
  - secret_b64: 43 chars URL-safe base64 (256 bits)

agent_api_keys.key_id stores: "agk_<public_id>"   (e.g. "agk_aB1cD2eF")
                              ^^^^^^^^^^^^^^^^
                              Full public part with prefix.

Regex: /^agk_([a-zA-Z0-9_-]{8})_([a-zA-Z0-9_-]{43})$/
                ^^^^^^^^^^^^^      ^^^^^^^^^^^^^^^
                public part        secret part

Parsing:
  match = req.headers.authorization.match(BEARER_REGEX)
  full_key = match[1]
  public_id_with_prefix = `agk_${match.split('_')[1]}`  // 'agk_aB1cD2eF'
  secret = match.split('_')[2]                            // 'xyz...'

Validation:
  SELECT FROM agent_api_keys WHERE key_id = $1 (= 'agk_aB1cD2eF')
  Argon2id_verify(secret, row.key_hash)
```

## Detail: minor fixes

### Remove /issue-key reference
v3 § "POST /issue-key" — DELETE entire section. Replace with note in /begin-registration: "If account already exists for this identity, response includes is_first_key: false and issues additional key."

Actually fix this properly:
```
On /begin-registration → /callback flow, after identity verification:
  IF existing_account_for_identity AND status='active':
    is_first_key = false
    issue NEW key (don't reuse existing)
    response includes is_first_key flag
  ELSE:
    is_first_key = true
    create account + identity + first key
```

This means: same flow, response differs. /issue-key is unnecessary endpoint.

### /recover-account vs /registration-status semantics

Conflict in v3: /recover-account uses poll_token from "fresh OAuth flow", but registration-status consumes poll_tokens.

v4 fix: Recovery uses a DIFFERENT poll_token namespace.

```ts
agent_registration_sessions.kind: 'register' | 'recover' | 'add_key'
```

`/recover-account` accepts only poll_tokens with kind='recover'.
`/begin-registration` body adds optional `intent: 'register' | 'recover' | 'add_key'`.

Lib enforces: a poll_token's kind is set at begin and immutable.

### Cache invalidation must DEL Redis

v3 said pubsub for "best-effort immediate eviction". Codex flags: pubsub only evicts subscribers' LOCAL caches. Redis cache entry persists until TTL.

v4:
```ts
// On revoke/rotate:
// 1. Update Postgres
// 2. Redis DEL 'agent-auth:key:<key_id>'   (server-side eviction)
// 3. Redis PUBLISH 'agent-auth:invalidate:key:<key_id>'  (notify other processes' local caches)
// All in the same transaction-like sequence; if step 3 fails, step 2 ensures TTL bound.
```

### Add tier to agent_api_keys

```sql
ALTER TABLE agent_api_keys ADD COLUMN tier TEXT NOT NULL DEFAULT 'cold' CHECK (tier IN ('cold','warm','hot'));
-- Updated when account.tier changes (cascade UPDATE in same transaction)
```

Or: drop tier from key cache, always read from account row at validation. Trade-off: extra JOIN per validation vs sync-on-update.

v0.1 choice: cache account.tier in agent_api_keys.tier, denormalized. Update via trigger or in-tx UPDATE on tier change.

```sql
CREATE TRIGGER trigger_sync_account_tier_to_keys
AFTER UPDATE OF tier ON agent_accounts
FOR EACH ROW
WHEN (OLD.tier IS DISTINCT FROM NEW.tier)
EXECUTE FUNCTION sync_account_tier_to_keys();

CREATE FUNCTION sync_account_tier_to_keys() RETURNS TRIGGER AS $$
BEGIN
  UPDATE agent_api_keys SET tier = NEW.tier
  WHERE account_id = NEW.id AND rotation_state IN ('active', 'rotating');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### Default scopes

```ts
issued_key.scopes = ['read', 'self:rotate', ...sass_owner_configured_default_scopes]
```

`self:rotate` always included so every key can rotate itself.

### req.agent immutability

```ts
function buildAgentContext(row: KeyRow): AgentContext {
  const scopes = Object.freeze([...row.scopes])
  const ctx: AgentContext = Object.freeze({
    account_id: row.account_id,
    key_id: row.key_id,
    identity: Object.freeze({...}),
    scopes,
    tier: row.tier,
    has_scope: (s: string) => scopes.includes(s),
    require_scope: (s: string) => {
      if (!scopes.includes(s)) {
        throw new AgentAuthError(403, 'insufficient_scopes', { required: s })
      }
    }
  })
  return ctx
}
```

`Object.freeze` makes mutation throw in strict mode (silent failure in non-strict, but still no actual mutation). For Node 22+ environments, this is reliable.

### GCRA fix

```lua
-- v4 corrected gcra.lua
local key = KEYS[1]
local period = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost = tonumber(ARGV[3] or 1)

if period <= 0 or burst <= 0 or cost < 1 or cost > burst then
  return redis.error_reply('GCRA: invalid params')
end

local rate = burst / period
local interval = cost / rate

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1e6

local last = redis.call('GET', key)
local tat = last and tonumber(last) or now

local allow_at = math.max(tat, now)
local new_tat = allow_at + interval
local delay_until_next_allowed = math.max(0, allow_at - now)

if (new_tat - now) > (burst / rate) then
  -- Reject. Return time until ANY request is allowed (not full TAT).
  return { 0, 0, math.ceil(delay_until_next_allowed * 1000) }
end

-- Accept
local ttl = math.ceil((new_tat - now) + period)
redis.call('SET', key, tostring(new_tat), 'EX', ttl)

local remaining_capacity_seconds = (burst / rate) - (new_tat - now)
local remaining_units = math.floor(remaining_capacity_seconds * rate)
return { 1, remaining_units, math.ceil((new_tat - now) * 1000) }
```

Test cases:
- burst=10, period=60s, cost=1: 10 requests immediate, 11th rejected, returns reset_after ~6000ms
- After waiting reset_after, request allowed
- cost=10 with burst=10: one request consumes all capacity, next reject reset=60s

### Audit meta scrubbing

```ts
const ALLOWED_META_KEYS = new Set([
  'request_id', 'duration_ms', 'response_status', 'request_size_bytes',
  'rate_limit_dimension', 'rate_limit_remaining',
  'tier_change_from', 'tier_change_to', 'tier_change_reason',
  'rotation_grace_seconds', 'rotation_reason'
])

const REDACT_KEY_PATTERNS = [
  /authorization/i, /x-api-key/i, /token/i, /secret/i, /password/i,
  /cookie/i, /credential/i, /private/i, /key$/i
]

const SECRET_VALUE_PATTERNS = [
  /^agk_[a-zA-Z0-9_-]+_[a-zA-Z0-9_-]+$/,    // our keys
  /^ghp_[a-zA-Z0-9]{36,}$/,                  // GitHub PAT
  /^github_pat_[a-zA-Z0-9_]+$/,              // GitHub fine-grained PAT
  /^sk-ant-[a-zA-Z0-9-]+$/,                  // Anthropic
  /^sk-[a-zA-Z0-9]{40,}$/                    // OpenAI
]

function scrubMeta(input: unknown, depth = 0): unknown {
  if (depth > 4) return '<MAX_DEPTH>'
  if (input === null || typeof input !== 'object') {
    if (typeof input === 'string') {
      for (const p of SECRET_VALUE_PATTERNS) {
        if (p.test(input)) return '<REDACTED_SECRET>'
      }
    }
    return input
  }
  if (Array.isArray(input)) {
    return input.slice(0, 100).map(v => scrubMeta(v, depth + 1))
  }
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(input)) {
    if (!ALLOWED_META_KEYS.has(k)) continue
    if (REDACT_KEY_PATTERNS.some(p => p.test(k))) {
      out[k] = '<REDACTED_KEY_NAME>'
      continue
    }
    out[k] = scrubMeta(v, depth + 1)
  }
  return out
}

// Total serialized JSON max size: 4KB. Reject larger.
```

## Round-4 audit questions for codex

1. Does client-encrypted secret delivery actually solve idempotency without introducing new replay paths?

2. Is the recovery state machine + multi-namespace poll_token logic clean, or did we just push the conflict elsewhere?

3. Walk through the complete revoke → cascade → cache invalidation → middleware chain. Any holes?

4. Reconciliation job is admittedly imperfect. What's the actual exposure window for a compromised user who revoked the GitHub App but still has a valid agent-auth key, given that they aren't actively using it?

5. Device flow encryption-at-rest: is SHA-256 of device_code as primary key OK (collision-resistant for indexing) plus AES-GCM for actual storage? Any timing attacks on lookup?

6. Audit meta scrubbing: any obvious bypass? E.g. base64-encoded secret in a non-redacted key.

7. GCRA Lua: is the new reset_after correct? Are there edge cases in cost > burst (we reject) vs cost == burst (allowed exactly once)?

8. Identity re-activation post-webhook-revocation: is "fresh OAuth" sufficient proof? What's the threat scenario where re-activation is wrong?

9. CHECK constraint `(revoked_at IS NULL) = (rotation_state != 'revoked')` — correct, or is there a state where this is briefly false during transitions?

10. Anything I missed AGAIN? B+ at this point or still B-?
