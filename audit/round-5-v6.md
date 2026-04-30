# agent-auth v6 spec (post round-5 audit)

Tight patch over v5. Round-5 graded B+. v6 targets A-/A.

## v6 changes summary

| v5 issue | v6 fix |
|---|---|
| 1. SQL `LIKE 'pak_%'` — `_` is LIKE wildcard | Use regex: `poll_token ~ '^pak_[A-Za-z0-9_-]{43}$'` |
| 2. `DEL agent-auth:account-keys:<id>` removes future enumeration | Do NOT delete set on invalidation. Set lives until account closure. |
| 3. Webhook replay skips when event row exists, even unprocessed | Skip only if `status='processed'`; reprocess if `status IN ('received','failed')` |
| 4. Recovery semantics for revoked-then-fresh-OAuth | Explicit: fresh OAuth → reactivate identity (if revocation_source allows) OR create new identity row linked to same account. Old keys stay revoked, new keys issued. |
| 5. GCRA `remaining` could be -1 from float math | Clamp `max(0, ...)` |
| 6. Webhook replay needs pagination + API version | Add Link header pagination + `X-GitHub-Api-Version: 2026-03-10` |
| 7. Sealed box agent private key lifecycle | Spec: agent must erase `agentKp.privateKey` after retrieval |
| 8. Cache uses `primary_identity.status` (deprecated) | Drop primary; use only `issuing_identity_status` |
| 9. Rotation trigger silent on 0 rows | RAISE EXCEPTION on inverse update returning 0 |
| 10. Audit entropy checks whole string, not substring | Tokenize on whitespace + delimiter, scan each token |
| 11. UUID/trace-id false positives | Explicit allow regexes for UUID, ULID, trace_id formats |

---

## Detail: Finding 1 — SQL LIKE wildcard fix

```sql
ALTER TABLE agent_registration_sessions
  DROP CONSTRAINT IF EXISTS poll_token_prefix_matches_kind;

ALTER TABLE agent_registration_sessions ADD CONSTRAINT poll_token_prefix_matches_kind CHECK (
  (kind = 'register' AND poll_token ~ '^pak_[A-Za-z0-9_-]{43}$') OR
  (kind = 'recover'  AND poll_token ~ '^pkr_[A-Za-z0-9_-]{43}$') OR
  (kind = 'add_key'  AND poll_token ~ '^pad_[A-Za-z0-9_-]{43}$')
);
```

Endpoint queries also use regex if a prefix check is needed:
```sql
-- /recover-account
SELECT * FROM agent_registration_sessions
WHERE poll_token = $1                                        -- exact match (fastest)
  AND kind = 'recover'                                       -- definitive boundary
  AND status = 'ready'
  AND expires_at > now();
-- (kind filter is the real defense; LIKE/regex avoided in hot path)
```

## Detail: Finding 2 — Redis account-key set lifecycle

```
Set lifecycle:
  Created on first key issued for account
  SADD on each new key issued
  SREM on each key revoked or rotated → 'rotated'
  Set deleted ONLY when account.status = 'closed' (terminal)
```

Invalidation does NOT delete the set. Reason: future invalidations need to enumerate.

```ts
async function invalidateAccountKeys(accountId: string) {
  const keyIds = await redis.smembers(`agent-auth:account-keys:${accountId}`)
  if (keyIds.length === 0) return

  const pipeline = redis.pipeline()
  for (const kid of keyIds) {
    pipeline.del(`agent-auth:key:${kid}`)
    pipeline.publish(`agent-auth:invalidate:key:${kid}`, '1')
  }
  // NOTE: Do NOT `pipeline.del('agent-auth:account-keys:...')`
  await pipeline.exec()
}

async function onAccountClosed(accountId: string) {
  await redis.del(`agent-auth:account-keys:${accountId}`)
}
```

Stale references in the set are harmless because the per-key entries are independently re-checked. SREM is best-effort cleanup, not a correctness primitive.

## Detail: Finding 3 — Webhook replay processed-state filter

```ts
for (const d of deliveries) {
  if (d.event !== 'github_app_authorization') continue

  // Successful delivery (200-299): trust GitHub processed it
  if (d.status_code >= 200 && d.status_code < 300) continue

  // Check OUR processing state
  const existing = await db.query(
    `SELECT status FROM agent_webhook_events WHERE id = $1`, [d.guid]
  )

  if (existing.rows.length > 0) {
    if (existing.rows[0].status === 'processed') continue   // already done
    // status IN ('received','failed'): retry
  }

  // Either no row (delivery never landed) or row exists but unprocessed/failed
  await fetch(`https://api.github.com/app/hook/deliveries/${d.id}/attempts`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${appJwt}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2026-03-10'
    }
  })
}
```

## Detail: Finding 4 — Recovery state semantics

```
Recovery scenario: User had GitHub identity, got webhook-revoked, now wants to recover.

Flow:
  1. POST /begin-registration { provider: 'github_app', intent: 'recover' }
     → Generates poll_token with 'pkr_' prefix, kind='recover'.
  2. User completes fresh OAuth (browser or device flow).
  3. /callback verifies, gets attestation { provider: 'github_app', subject: <numeric_id>, audience }.
  4. Lib looks up:
     SELECT * FROM agent_identities
     WHERE provider = 'github_app' AND subject = ? AND audience = ?
     FOR UPDATE;

     If row exists with status='revoked' AND revocation_source IN ('webhook','expiry'):
       UPDATE status='active', revoked_at=NULL, revoked_reason=NULL,
              revocation_source=NULL, last_revalidated_at=now()
       WHERE id = identity.id;

     If row exists with status='revoked' AND revocation_source IN ('manual','cascade'):
       REJECT (409 identity_blocked, message='Manual revocation requires owner approval')

     If row exists with status='active':
       Use as-is (no change)

     If no row exists (new identity for an existing account?):
       This case requires explicit owner approval webhook (recover_account.require_owner_approval).
       Otherwise reject.
  5. Lookup the account:
     SELECT account_id FROM agent_identities WHERE id = identity.id;
  6. Old keys: stay revoked (do not resurrect).
     Issue NEW key with issued_via_identity_id=identity.id.
  7. Encrypt and store result_ciphertext (sealed box).
  8. Status='ready'.
  9. Agent polls /recover-account with poll_token, gets new key.
```

**Important:** Recovery does NOT resurrect old keys, only issues new ones. Old key revocations are immutable history.

**Edge case:** account has multiple identities, primary GitHub revoked, user reauthenticates via Anthropic. This is an "add identity" flow not strictly recovery, gated by owner approval (anti-takeover).

## Detail: Finding 5 — GCRA remaining clamp

```lua
-- Final return for accept path:
local remaining_capacity = (burst / rate) - (new_tat - now)
local remaining_units = math.max(0, math.floor(remaining_capacity * rate))
return { 1, remaining_units, math.ceil((new_tat - now) * 1000) }
```

Float edge case: `remaining_capacity` can be very slightly negative due to FP rounding when at exact capacity. Clamp.

Also rename return semantics:
- Accept: `{ 1, remaining_units, reset_after_ms }`
- Reject: `{ 0, 0, retry_after_ms }`

Consumer code distinguishes by first element.

## Detail: Finding 6 — Webhook replay pagination

```ts
async function reconcileWebhookDeliveries() {
  const appJwt = await mintGithubAppJwt(...)
  let url: string | null = 'https://api.github.com/app/hook/deliveries?per_page=100'

  while (url) {
    const resp = await fetch(url, {
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2026-03-10'
      }
    })
    if (!resp.ok) {
      log.warn('webhook_delivery_poll_failed', { status: resp.status })
      break
    }
    const deliveries = await resp.json()
    for (const d of deliveries) await processDelivery(d)

    // Pagination via Link header
    const link = resp.headers.get('Link') ?? ''
    const next = link.split(',').find(s => s.includes('rel="next"'))
    url = next ? next.match(/<([^>]+)>/)?.[1] ?? null : null

    // Safety: limit to 10 pages (1000 deliveries) per run
    if (page > 10) break
  }
}
```

## Detail: Finding 7 — Sealed box client key lifecycle

Documentation requirement (in agent SDK):

```ts
class AgentRegistrar {
  private agentKp: { publicKey: Uint8Array, privateKey: Uint8Array } | null = null

  async beginRegistration(...): Promise<RegisterChallenge> {
    this.agentKp = sodium.crypto_box_keypair()
    return { ..., client_pubkey: base64url(this.agentKp.publicKey) }
  }

  async pollRegistrationStatus(pollToken: string): Promise<KeyMaterial> {
    if (!this.agentKp) throw new Error('No active registration session')
    const resp = await fetch(...)
    const { encrypted_payload } = await resp.json()
    const decrypted = sodium.crypto_box_seal_open(
      base64url_decode(encrypted_payload),
      this.agentKp.publicKey,
      this.agentKp.privateKey
    )
    // CRITICAL: Erase private key after use
    sodium.memzero(this.agentKp.privateKey)
    this.agentKp = null
    return JSON.parse(Buffer.from(decrypted).toString('utf8'))
  }
}
```

`sodium.memzero` overwrites the buffer. Forward secrecy holds even if process memory is later dumped (best effort; OS may retain pages).

Server-side authenticity comes from TLS (HTTPS) + session binding via poll_token (only the agent that called begin-registration knows the token).

## Detail: Finding 8 — Drop primary_identity.status check

```ts
// v5 cache:
interface KeyCache {
  ...
  issuing_identity_id: string
  issuing_identity_status: 'active' | 'revoked'
  // primary_identity_status: REMOVED in v6
}

// Validation:
//  - account.status === 'active'
//  - cache.rotation_state in ('active', 'rotating' with grace not expired)
//  - cache.revoked_at is null
//  - cache.expires_at is null OR > now()
//  - cache.issuing_identity_status === 'active'
//
// No primary_identity check. A key is valid iff its issuing identity is active.
```

`is_primary` on agent_identities remains for UX (which identity is shown in account dashboard), but does not affect key auth.

## Detail: Finding 9 — Rotation trigger raises on 0 rows

```sql
CREATE FUNCTION enforce_rotation_inverse() RETURNS TRIGGER AS $$
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
```

If two concurrent /rotate-key calls race past the SELECT FOR UPDATE (e.g. via direct DB access), the trigger blocks the second insert.

## Detail: Finding 10 — Audit substring entropy scanning

```ts
// Tokenize string on whitespace + common delimiters, scan each chunk
function scanForHighEntropyTokens(s: string): boolean {
  const tokens = s.split(/[\s,;:|"'<>(){}\[\]]+/).filter(t => t.length >= 32)
  for (const t of tokens) {
    if (UUID_REGEX.test(t)) continue       // UUIDs allowed
    if (ULID_REGEX.test(t)) continue       // ULIDs allowed
    if (TRACE_ID_REGEX.test(t)) continue   // OpenTelemetry trace_id (32 hex) allowed
    if (shannonBitsPerChar(t) >= 4.5) return true
  }
  return false
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const ULID_REGEX = /^[0-9A-HJKMNP-TV-Z]{26}$/i
const TRACE_ID_REGEX = /^[0-9a-f]{32}$/i

function scrubValue(v: unknown, depth = 0): unknown {
  // ... same shape as v5, but string handling:
  if (typeof v === 'string') {
    if (v.length > 1024) return `<TRUNCATED:${v.length}>`
    for (const p of SECRET_VALUE_PATTERNS) if (p.test(v)) return '<REDACTED_PATTERN>'
    if (/agk_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}/.test(v)) return '<REDACTED_INLINE>'
    if (scanForHighEntropyTokens(v)) return '<REDACTED_HIGH_ENTROPY>'
    return v
  }
  // ... rest same as v5
}
```

## Round-6 audit questions

1. Are all four "must-fix" v5 items now correctly addressed in v6?

2. The recovery flow now distinguishes 4 cases (active → reuse, revoked-webhook → reactivate, revoked-manual → block, no-row → owner-gated). Is this complete? Any 5th case?

3. The audit entropy tokenizer splits on delimiters then scans tokens ≥32 chars. Is this robust to: (a) keys embedded in URLs (`?token=agk_...`), (b) keys in JSON ("token":"agk_..."), (c) keys in headers ("Authorization: Bearer agk_...")?

4. The rotation trigger raises on 0 rows. Does this correctly handle the case where `/rotate-key` is called with grace_seconds=0 (emergency, no grace)?

5. The webhook replay pagination caps at 10 pages = 1000 deliveries per run. Is this enough to catch up after a long outage? Should it be configurable?

6. Sealed box: agent erases private key after first successful decrypt. What if the first decrypt fails (e.g. corrupted ciphertext)? Should agent retry with same key, or treat as terminal failure?

7. Account-key Redis SET: never deleted except on account closure. Is there a memory leak risk if accounts have very high key churn (e.g. CI rotating keys hourly for a year)? SREM keeps it bounded but unbounded if SREMs are missed.

8. v6 grade. Is this minimum acceptable now, or are there still must-fix items?
