# agent-auth v5 spec (post round-4 audit)

Focused patch over v4. Round-4 graded B. v5 targets B+/A-. Reference v3+v4 for unchanged content.

## v5 changes summary

| v4 issue | v5 fix |
|---|---|
| 1. GCRA reset_after still wrong | Formula: `retry_after = max(0, new_tat - now - burst/rate)`. Validate inputs. |
| 2. GitHub re-verification path doesn't exist | Switch to webhook delivery replay: poll `GET /app/hook/deliveries` with app JWT, redeliver missed `github_app_authorization` events. NO user token storage. |
| 3. Key parsing splits on `_`, breaks on base64url | Regex capture groups only. |
| 4. Cache invalidation not atomic, account-wide enum missing | Document 30s worst-case; add Redis SET `agent-auth:account-keys:<id>` for enumeration. |
| 5. Webhook dedup ON CONFLICT DO UPDATE overwrites mismatch evidence | DO NOTHING RETURNING + separate SELECT for mismatch detection. |

Plus refinements:
- Client-encrypted delivery: use `sodium.crypto_box_seal` (anonymous sealed box). No derived server keys.
- Poll-token namespace: cryptographic prefix per kind + DB query-level enforcement.
- Multi-identity validation: middleware checks `issued_via_identity` status, not only primary.
- Audit scrubbing: high-entropy detection + substring scan + length cap.
- UNIQUE on rotation: keep BOTH `created_by_key_id` AND `replaced_by_key_id`.
- Device flow slow_down: status stays 'pending', interval bumped.
- Tier sync invalidation: trigger enqueues async cache eviction job.

---

## Detail: Finding 1 — GCRA corrected

```lua
-- v5 gcra.lua
local key = KEYS[1]
local period = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local cost = tonumber(ARGV[3] or 1)

if not period or not burst or not cost then
  return redis.error_reply('GCRA: missing/invalid params')
end
if period <= 0 or burst <= 0 or cost < 1 or cost > burst then
  return redis.error_reply('GCRA: out-of-range params')
end

local rate = burst / period          -- units per second
local interval = cost / rate         -- seconds for this cost

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1e6

local last = redis.call('GET', key)
local tat = (last and tonumber(last)) or now

local allow_at = math.max(tat, now)
local new_tat = allow_at + interval

-- Check capacity: new_tat - now must be <= burst/rate (= period)
if (new_tat - now) > (burst / rate) then
  -- Rejected. retry_after is time until budget would allow this exact cost.
  local retry_after = math.max(0, new_tat - now - (burst / rate))
  return { 0, 0, math.ceil(retry_after * 1000) }
end

-- Accepted. Persist new TAT.
local ttl = math.ceil((new_tat - now) + period)
redis.call('SET', key, tostring(new_tat), 'EX', ttl)

local remaining = math.floor(((burst / rate) - (new_tat - now)) * rate)
return { 1, remaining, math.ceil((new_tat - now) * 1000) }
```

**Test cases (must pass):**
```
T0: burst=10, period=60, cost=1, current=empty
   req 1..10 immediate: { allowed=1, remaining=9..0 }
   req 11: { allowed=0, remaining=0, retry_after≈6000ms }

T0+6s: req 12: { allowed=1, remaining=0, retry_after=60000ms (full reset)}

T0: burst=10, period=60, cost=10
   req 1: { allowed=1, remaining=0, retry_after=60000ms }
   req 2 (immediate): { allowed=0, retry_after≈60000ms }

cost > burst: redis.error_reply('GCRA: out-of-range params')
```

## Detail: Finding 2 — GitHub webhook delivery replay

GitHub does NOT auto-redeliver. v5 switches to active polling of webhook deliveries:

```ts
// Background job runs every 5 minutes
async function reconcileWebhookDeliveries() {
  const appJwt = await mintGithubAppJwt(githubApp.app_id, githubApp.private_key)

  // GET /app/hook/deliveries — list recent deliveries to OUR app's webhook
  const deliveries = await fetch('https://api.github.com/app/hook/deliveries', {
    headers: { Authorization: `Bearer ${appJwt}`, Accept: 'application/vnd.github+json' }
  }).then(r => r.json())

  for (const d of deliveries) {
    // Skip already-processed (UNIQUE on agent_webhook_events.id catches dups)
    const existing = await db.query(
      'SELECT id FROM agent_webhook_events WHERE id = $1', [d.guid]
    )
    if (existing.rows.length > 0) continue

    // Skip if not a github_app_authorization event
    if (d.event !== 'github_app_authorization') continue

    // Skip if delivery succeeded (don't redeliver successful)
    if (d.status_code >= 200 && d.status_code < 300) continue

    // Redeliver: POST /app/hook/deliveries/{delivery_id}/attempts
    await fetch(`https://api.github.com/app/hook/deliveries/${d.id}/attempts`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${appJwt}`, Accept: 'application/vnd.github+json' }
    })
  }
}
```

This relies on GitHub's documented API. NO user/refresh token storage. NO active token-check API call (which would require user token).

Trade-off: still some delay (up to 5min poll interval + GitHub redelivery). Acceptable because:
- Active attackers using a key trigger re-verification on the request itself (existing finding 4 in v4)
- Idle revoked keys are not active threats

**Reconciliation cadence config:**
```ts
agentAuth({
  reconciliation: {
    webhook_deliveries_poll_interval_seconds: 300,   // every 5 min
    enabled: true
  }
})
```

## Detail: Finding 3 — Key parsing regex only

```ts
const KEY_REGEX = /^agk_([A-Za-z0-9_-]{8})_([A-Za-z0-9_-]{43})$/

function parseKey(authHeader: string): { key_id: string, secret: string } | null {
  const bearer = authHeader.match(/^Bearer\s+(\S+)$/)
  if (!bearer) return null
  const m = bearer[1].match(KEY_REGEX)
  if (!m) return null
  return { key_id: `agk_${m[1]}`, secret: m[2] }
}
```

`split('_')` is BANNED in any code path that touches keys. Lint rule (eslint custom): forbid `.split('_')` in files matching `keys/*.ts`.

## Detail: Finding 4 — Cache invalidation honest documentation + account-wide enumeration

**Documented properties:**
1. **Worst-case revocation latency: 30 seconds** (= cache TTL).
2. Pubsub-driven local cache eviction is best-effort acceleration, NOT a guarantee.
3. Redis cache `DEL` is server-side cooperative; if any process fails to subscribe, only TTL bounds.
4. Operators concerned with sub-30s revocation should set `cache_ttl_seconds: 0` (disables cache, +1 DB query per request).

**Account→keys enumeration (new):**

Maintain a Redis SET per account with key_ids:

```
SET agent-auth:account-keys:<account_id>  ← contains all key_ids for account
```

Updated on:
- Key issued: SADD account-keys:<account_id> <key_id>
- Key revoked/rotated: SREM account-keys:<account_id> <key_id>

On account-wide invalidation (suspension, tier change, primary identity revoked):
```ts
const keyIds = await redis.smembers(`agent-auth:account-keys:${accountId}`)
const pipeline = redis.pipeline()
for (const kid of keyIds) {
  pipeline.del(`agent-auth:key:${kid}`)
  pipeline.publish(`agent-auth:invalidate:key:${kid}`, '1')
}
pipeline.del(`agent-auth:account-keys:${accountId}`)
await pipeline.exec()
```

If pipeline fails midway: re-publish acceptable (idempotent), DEL is idempotent. Worst case: TTL.

## Detail: Finding 5 — Webhook dedup uses DO NOTHING + separate SELECT

```sql
-- v5: single transaction
BEGIN;

-- Step 1: HMAC verified (in app code, before this transaction)

-- Step 2: try insert
WITH inserted AS (
  INSERT INTO agent_webhook_events (id, provider, event_type, payload_hash, received_at, status)
  VALUES ($1, $2, $3, $4, now(), 'received')
  ON CONFLICT (id) DO NOTHING
  RETURNING id
)
SELECT
  CASE WHEN EXISTS (SELECT 1 FROM inserted) THEN 'new' ELSE 'duplicate' END AS result;

-- If 'new': proceed with processing in same transaction or async.
-- If 'duplicate':
SELECT payload_hash FROM agent_webhook_events WHERE id = $1;
-- Compare to incoming. If mismatch:
--   - INSERT INTO agent_webhook_alerts (event_id, kind, ...)
--   - LOG.alert('webhook_id_collision: id=$1 expected_hash=$2 got_hash=$3')
--   - Return 200 (do not re-process; existing record wins)
-- If match: return 200 (already processed, no-op).

COMMIT;
```

## Detail: Client-encrypted delivery via sealed box

```ts
import sodium from 'libsodium-wrappers'

// Agent side (before begin-registration)
const agentKp = sodium.crypto_box_keypair()
// Send agentKp.publicKey to server, keep agentKp.privateKey local.

// Server side (after key issuance)
const payload = JSON.stringify({ key_secret, key_id, account_id, scopes, tier, is_first_key })
const ciphertext = sodium.crypto_box_seal(
  Buffer.from(payload, 'utf8'),
  Buffer.from(session.client_pubkey, 'base64')
)
// Store ciphertext (no IV needed; sealed_box embeds it).
// NO sender private key needed — sealed_box is anonymous public-key encryption.

// Agent side (on registration-status response)
const decrypted = sodium.crypto_box_seal_open(
  Buffer.from(response.encrypted_payload, 'base64'),
  agentKp.publicKey,
  agentKp.privateKey
)
const { key_secret, ... } = JSON.parse(decrypted.toString('utf8'))
```

**Schema update:**
```sql
ALTER TABLE agent_registration_sessions
  DROP COLUMN lib_pubkey,
  DROP COLUMN box_nonce;
-- Only client_pubkey and result_ciphertext (sealed box) remain.
```

**Security property:** Even if `internal_secret` is later compromised, past session ciphertexts cannot be decrypted (only the agent's ephemeral private key can decrypt, and that never left agent process).

## Detail: Poll-token namespace cryptographic enforcement

```ts
type PollTokenKind = 'register' | 'recover' | 'add_key'

const PREFIX_BY_KIND: Record<PollTokenKind, string> = {
  register: 'pak_',
  recover:  'pkr_',
  add_key:  'pad_'
}

function generatePollToken(kind: PollTokenKind): string {
  const random = sodium.randombytes_buf(32)  // 256 bits
  return PREFIX_BY_KIND[kind] + base64url(random)
}

function parsePollTokenKind(token: string): PollTokenKind | null {
  for (const [kind, prefix] of Object.entries(PREFIX_BY_KIND)) {
    if (token.startsWith(prefix)) return kind as PollTokenKind
  }
  return null
}
```

```sql
-- Prefix-kind consistency CHECK
ALTER TABLE agent_registration_sessions ADD CONSTRAINT poll_token_prefix_matches_kind CHECK (
  (kind = 'register' AND poll_token LIKE 'pak_%') OR
  (kind = 'recover'  AND poll_token LIKE 'pkr_%') OR
  (kind = 'add_key'  AND poll_token LIKE 'pad_%')
);
```

**SQL-level enforcement at endpoint boundaries:**
```sql
-- /recover-account
SELECT * FROM agent_registration_sessions
WHERE poll_token = $1 AND kind = 'recover' AND status = 'ready' AND expires_at > now();

-- /registration-status (covers register + add_key)
SELECT * FROM agent_registration_sessions
WHERE poll_token = $1 AND kind IN ('register', 'add_key') AND status = 'ready' AND expires_at > now();
```

A register-kind token sent to /recover-account returns `404 not_found` at the DB level. No application-layer kind check needed.

## Detail: Middleware validates issuing identity

```ts
// Cache value extended:
interface KeyCache {
  account_id: string
  account_status: 'active' | 'suspended' | 'closed'
  key_hash: Buffer
  scopes: string[]
  tier: 'cold' | 'warm' | 'hot'
  rotation_state: 'active' | 'rotating' | 'rotated' | 'revoked'
  revoked_at: Date | null
  rotation_grace_expires_at: Date | null
  expires_at: Date | null
  issuing_identity_id: string                    // NEW
  issuing_identity_status: 'active' | 'revoked'  // NEW
}

// Validation (added):
if (cache.issuing_identity_status !== 'active') {
  return reject(401, 'issuing_identity_revoked')
}
```

Cascade rule: when an identity is revoked, ALL keys with `issued_via_identity_id = identity.id` are immediately revoked, regardless of whether other identities on the same account are still active. This means:
- If user has both GitHub and Anthropic identities, and GitHub is revoked, only GitHub-issued keys die. Anthropic-issued keys survive.
- Account stays 'active' as long as any identity is active.

## Detail: UNIQUE on rotation — keep both

```sql
-- Each old key has at most ONE successor
CREATE UNIQUE INDEX agent_api_keys_one_predecessor
  ON agent_api_keys(created_by_key_id) WHERE created_by_key_id IS NOT NULL;

-- Each new key has at most ONE predecessor
CREATE UNIQUE INDEX agent_api_keys_one_successor
  ON agent_api_keys(replaced_by_key_id) WHERE replaced_by_key_id IS NOT NULL;
```

These together enforce strict 1:1 rotation. `created_by_key_id` and `replaced_by_key_id` are denormalized inverses; trigger keeps them consistent:

```sql
CREATE FUNCTION enforce_rotation_inverse() RETURNS TRIGGER AS $$
BEGIN
  IF NEW.created_by_key_id IS NOT NULL THEN
    UPDATE agent_api_keys
    SET replaced_by_key_id = NEW.id
    WHERE id = NEW.created_by_key_id AND replaced_by_key_id IS NULL;
    -- If 0 rows updated: another tx already linked. UNIQUE constraints catch this.
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_enforce_rotation_inverse
AFTER INSERT ON agent_api_keys
FOR EACH ROW EXECUTE FUNCTION enforce_rotation_inverse();
```

## Detail: Device flow slow_down handling

```ts
// On polling result from GitHub
switch (response.error) {
  case 'authorization_pending':
    await db.query(`
      UPDATE agent_device_flows
      SET next_poll_at = now() + (poll_interval_seconds || ' seconds')::interval
      WHERE device_code_hash = $1
    `, [hash])
    break
  case 'slow_down':
    await db.query(`
      UPDATE agent_device_flows
      SET poll_interval_seconds = poll_interval_seconds + 5,
          next_poll_at = now() + ((poll_interval_seconds + 5) || ' seconds')::interval
      WHERE device_code_hash = $1
    `, [hash])
    // status stays 'pending', not 'slow_down'
    break
  case 'expired_token':
    await db.query(`UPDATE agent_device_flows SET status = 'expired' WHERE device_code_hash = $1`, [hash])
    // also mark session 'failed'
    break
  // success path: status = 'authorized', complete OAuth as if browser flow returned
}
```

## Detail: Tier sync invalidation

```sql
CREATE FUNCTION sync_account_tier_to_keys() RETURNS TRIGGER AS $$
DECLARE
  affected_key_ids TEXT[];
BEGIN
  UPDATE agent_api_keys SET tier = NEW.tier
  WHERE account_id = NEW.id AND rotation_state IN ('active', 'rotating')
  RETURNING ARRAY_AGG(key_id) INTO affected_key_ids;

  -- Enqueue cache invalidation job
  INSERT INTO agent_jobs (kind, payload, run_at)
  VALUES ('cache_invalidate_keys', jsonb_build_object('key_ids', affected_key_ids), now());

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

`agent_jobs` is a simple internal queue table polled by background worker. No external deps.

## Detail: Audit scrubbing with high-entropy detection

```ts
function scrubValue(v: unknown, depth = 0): unknown {
  if (depth > 4) return '<MAX_DEPTH>'
  if (v === null || typeof v === 'undefined') return v
  if (typeof v === 'string') {
    if (v.length > 1024) return '<TRUNCATED:' + v.length + '>'
    // Direct pattern match
    for (const p of SECRET_VALUE_PATTERNS) if (p.test(v)) return '<REDACTED>'
    // Substring scan: 'Bearer agk_...' inside arbitrary text
    if (/agk_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}/.test(v)) return '<REDACTED_INLINE>'
    // High entropy heuristic: any 32+ char run that's >= 4.5 bits/char Shannon entropy
    if (v.length >= 32 && shannonBitsPerChar(v) >= 4.5) {
      // Could be a token. Conservative: redact.
      return '<HIGH_ENTROPY_REDACTED>'
    }
    return v
  }
  if (typeof v === 'number' || typeof v === 'boolean') return v
  if (Array.isArray(v)) return v.slice(0, 100).map(x => scrubValue(x, depth + 1))
  if (typeof v === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, val] of Object.entries(v)) {
      if (!ALLOWED_META_KEYS.has(k)) continue
      if (REDACT_KEY_PATTERNS.some(p => p.test(k))) {
        out[k] = '<REDACTED_KEY_NAME>'
      } else {
        out[k] = scrubValue(val, depth + 1)
      }
    }
    return out
  }
  return v
}

function shannonBitsPerChar(s: string): number {
  const counts = new Map<string, number>()
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1)
  let h = 0
  for (const c of counts.values()) {
    const p = c / s.length
    h -= p * Math.log2(p)
  }
  return h
}
```

Allowed `tier_change_reason` values are now also length-capped and entropy-checked.

## Round-5 audit questions for codex

1. Does the GCRA fix correctly handle: (a) cost == burst, (b) cost in (1, burst), (c) immediately after a full reset window passes?

2. Does the webhook delivery replay (poll `/app/hook/deliveries`, `POST /attempts`) actually exist as written in GitHub API? If not, what's the corrected approach?

3. Sealed box delivery: is sodium.crypto_box_seal correct for this use case? Any forward secrecy concerns?

4. Poll-token cryptographic prefix + DB-level CHECK + SQL kind-filter at endpoint — any escape hatches?

5. Issuing identity status check: now we have account.status, primary_identity.status (deprecated?), issuing_identity.status. Is the cache layout right? Any redundant checks?

6. Both UNIQUE indexes on rotation + trigger: any way to mint two successors via concurrent INSERTs that both pass UNIQUE before constraint check? Phantom read at READ COMMITTED level?

7. Account→keys Redis SET enumeration: any race between SADD on issue and SREM on revoke that leaks references?

8. Audit high-entropy heuristic: false-positive rate for legitimate request_ids (UUIDs are high-entropy)? Should we exclude UUID format?

9. /recover-account specifically: what happens if user's GitHub identity is webhook-revoked, then user wants to recover via fresh OAuth — does the v4 reactivation flow handle this, or does recovery need new-identity-creation logic?

10. v5 grade. Is this minimum-acceptable-compromise yet, or are there blocking findings that push v6?
