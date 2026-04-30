# agent-auth: Production Specification v1.0

**Status**: design ceiling reached (codex round-13: A spec / production-ready paying-customer design level).
**Audit history**: see `audit/round-{1..13}-*.md` for 13-round design evolution.
**Implementation status**: pending.

This is the comprehensive specification. An AI coding agent or human engineering team should be able to implement v0.1 from this document without re-asking for clarification on protocol or schema details.

## Table of contents

- [Part I — Foundations](#part-i--foundations)
- [Part II — Identity & Protocol](#part-ii--identity--protocol)
- [Part III — Data Layer](#part-iii--data-layer)
- [Part IV — Distributed System Design](#part-iv--distributed-system-design)
- [Part V — Reliability Engineering](#part-v--reliability-engineering)
- [Part VI — Security & Threat Model](#part-vi--security--threat-model)
- [Part VII — Observability](#part-vii--observability)
- [Part VIII — Operations & Runbooks](#part-viii--operations--runbooks)
- [Part IX — Compliance (SOC 2, GDPR, Supply Chain)](#part-ix--compliance)
- [Part X — API Reference](#part-x--api-reference)
- [Part XI — Implementation Plan](#part-xi--implementation-plan)
- [Part XII — Testing Strategy](#part-xii--testing-strategy)
- [Part XIII — Deployment Topology](#part-xiii--deployment-topology)
- [Appendix A — Glossary](#appendix-a--glossary)
- [Appendix B — Decision Log](#appendix-b--decision-log)

---

# Part I — Foundations

## 1.1 Mission

Make it possible for an AI agent acting on behalf of a real human user to register a new account at a SaaS provider programmatically and receive a scoped, revocable API key, without requiring the SaaS to abandon its existing human auth, change its pricing model, or solve CAPTCHA / email verification on the agent's behalf.

The library is mounted by the SaaS as a parallel auth rail. Existing human auth is untouched.

## 1.2 Architectural tenets

These are the load-bearing decisions. Every later choice flows from these.

1. **Parallel rail, not replacement.** Lib mounts on separate route prefix (`/api/agent-auth`, `/api/agent/v1`). SaaS keeps its existing auth. Confused-deputy bugs prevented by typed `req.agent` distinct from `req.user`.

2. **Delegate KYC to upstream.** Lib does not run identity verification. It verifies the agent holds proof of an identity already KYC'd by GitHub / Anthropic / Stripe. Sybil cost = cost of upstream identity + IP diversity + waiting period.

3. **Lib never holds long-lived user credentials.** GitHub OAuth tokens are exchanged server-side and discarded. Agent's API key is delivered via sealed-box encryption (recipient-only-decryptable) so even lib operators cannot read past secrets.

4. **Postgres is authoritative. Redis is acceleration.** Cache invalidation must always have correct DB fallback. Account-wide enumeration always queries DB, not Redis SET.

5. **Tier B operations are durably replicated before ack.** Revocations, emergency rotations, account suspensions use `synchronous_commit = remote_apply`. Standby ack is required. If standby unreachable, ops fail closed (503).

6. **Authoritative state never inferred from a stale source.** Validation in secondary regions reads barrier LSN from primary (writer), not from local replica. Local replica trusted only for `pg_last_wal_replay_lsn()` comparison.

7. **Failover is not best-effort.** App readiness gates fail closed on timeline mismatch. Service does not resume serving requests until post-promotion reset script succeeds.

8. **External immutable audit.** S3 Object Lock COMPLIANCE in separate AWS account. KMS in another separate account. Even root account compromise cannot rewrite history within retention window.

9. **State machines, not booleans.** Account / identity / key / session / idempotency states are exhaustive enums with explicit transitions enforced by triggers. Unknown values fail closed.

10. **Spec is the source of truth.** Protocol details are spec'd; implementation has no degrees of freedom for security-critical paths.

## 1.3 Component overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  SaaS backend (existing app code, untouched by lib)                 │
│                                                                     │
│  ┌────────────────────┐         ┌──────────────────────────────┐    │
│  │ Existing human auth │         │ agent-auth library          │    │
│  │  (Better Auth,      │         │                              │    │
│  │   Clerk, custom)    │         │  Public endpoints:           │    │
│  └────────────────────┘         │   /api/agent-auth/*         │    │
│           │                     │   /.well-known/agent-auth   │    │
│           │ untouched           │                              │    │
│           ▼                     │  Middleware:                 │    │
│  /api/v1/* (humans)             │   /api/agent/v1/*           │    │
│                                 │   → req.agent populated     │    │
│                                 │                              │    │
│                                 │  Internal callbacks:         │    │
│                                 │   /api/agent-auth/callback   │    │
│                                 │   /api/agent-auth/webhooks   │    │
│                                 └──────────────────────────────┘    │
│                                       │     │     │                 │
│                                       ▼     ▼     ▼                 │
│                            ┌──────────┴─────┴─────┴──────┐          │
│                            │  Postgres (authoritative)   │          │
│                            │  Redis (cache + GCRA + epoch│          │
│                            │  S3 Object Lock (audit WORM)│          │
│                            │  KMS (peppers + sealed box) │          │
│                            └─────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
                                       ▲
                                       │ via OAuth
                                       │
┌──────────────────────────────────────┴───────────────────────────────┐
│  External identity providers                                        │
│   - GitHub (App OAuth + PKCE; webhook github_app_authorization)    │
│   - Anthropic (signed attestation, future)                          │
│   - Stripe Connect (future, for hot-tier upgrade)                   │
└──────────────────────────────────────────────────────────────────────┘

                                       ▲
                                       │ HTTPS
                                       │
┌──────────────────────────────────────┴───────────────────────────────┐
│  AI agent (Claude Code / Cursor / etc.)                             │
│   1. Generate ephemeral X25519 keypair                              │
│   2. POST /begin-registration { client_pubkey }                     │
│   3. Open OAuth challenge URL (browser or device flow)              │
│   4. Poll /registration-status                                      │
│   5. Decrypt sealed-box payload with private key                    │
│   6. Use API key for subsequent /api/agent/v1/* calls               │
└──────────────────────────────────────────────────────────────────────┘
```

## 1.4 Scope

### In scope (v0.1)

- Identity verification via GitHub App (browser flow + device flow)
- Account / identity / key data model with full lifecycle
- Registration / rotation / revocation / recovery flows
- Sealed-box delivery of issued secrets
- Per-key Argon2-free (HMAC + KMS pepper) verification
- Multi-dimensional GCRA rate limiting
- Tiered keys (cold / warm / hot) with risk scoring
- Tier A / Tier B durability classification
- Single-region deployment with active-passive multi-region option
- Cache invalidation via Redis pubsub + DEL + epoch versioning
- WORM external audit log (S3 Object Lock COMPLIANCE)
- Hash-chain in-DB audit log
- Admin CLI with WebAuthn / two-person rule
- Forced fresh OAuth revalidation (default path)
- Webhook reconciliation (active polling within GitHub's 3-day window)
- Disaster recovery runbooks (RB-1 through RB-8)
- 44-scenario threat model with concrete mitigations
- SOC 2 control mapping (CC6, CC7, CC8, CC9)
- GDPR right-to-erasure with crypto-erasure path
- Supply chain hardening (SLSA L3 target, npm trusted publishing OIDC)

### Out of scope (v0.1)

- Browser automation (use Browserbase / Skyvern)
- Cross-SaaS portable identity (different problem space)
- Inter-agent A2A communication (different problem space)
- Agent governance / policy enforcement (Microsoft AGT)
- Active-active multi-region (deferred to v0.2+)
- Real-time observability dashboard UI (logs/metrics only)
- LLM-based abuse detection (heuristic only)
- Payment integration (SaaS owner provides own promotion hook)
- Email verification provider (use existing email infra, optional plug-in)
- SMS / phone verification (defeats agent autonomy thesis)

### Deliberate compromises (acknowledged with rationale)

| Compromise | Reason | Recovery path |
|---|---|---|
| 30s worst-case revocation latency in `bounded_stale_1s` mode | Cache acceleration trade-off; strict mode is uncached primary read | Operators set `barrier_mode: strict_uncached` for paying customers |
| Multi-dimensional rate limit not atomic across Redis hash slots | Cluster constraint; same-slot dimensions are atomic | Single Redis primary works for v0.1 scale; reservation-based atomic multi-dim deferred to v0.2 |
| Risk score is heuristic, gameable by patient attacker | True Sybil resistance requires payment / strong attestation | Hot tier requires manual promotion; warm tier doesn't unlock expensive ops |
| GitHub redelivery limited to 3 days | GitHub-side limit, not lib-side | Forced fresh OAuth on next user activity covers > 3 day outages |
| Per-subject KMS keys expensive at scale | Real cost concern | Shared-pepper fallback documented as "minimization, not erasure" |

## 1.5 Non-functional requirements

| Property | Target | Measured by |
|---|---|---|
| Validation latency P50 (cache hit, same AZ) | < 5ms | histogram metric `agent_auth_validation_latency_seconds` |
| Validation latency P99 (cache hit, same AZ) | < 50ms | same |
| Validation latency P50 (cache miss, same AZ, with HMAC) | < 30ms | same |
| Validation latency P99 (cache miss, same AZ) | < 100ms | same |
| Registration P50 (excluding upstream IdP) | < 200ms | metric `agent_auth_registration_total_duration_seconds` |
| Webhook processing P50 | < 100ms | metric `agent_auth_webhook_events_total` |
| Cache hit rate (steady state) | > 95% | derived metric |
| Tier B revocation visibility (strict mode) | < 100ms post-ack | integration test `revoke_visibility_test.ts` |
| Tier B revocation visibility (bounded_stale_1s mode) | < 1s post-ack | same |
| Failover RTO | < 1 hour | DR drill quarterly |
| Failover RPO (Tier A operations) | < 5 minutes | Postgres WAL streaming lag |
| Failover RPO (Tier B operations) | 0 (synchronous replication) | by construction |
| Audit log durability | 11 nines (S3 Object Lock) | AWS SLA |


---

# Part II — Identity & Protocol

## 2.1 Identity provider abstraction

The lib supports multiple identity providers via a uniform interface. Each provider implements four lifecycle methods.

```typescript
interface AttestationContext {
  audience: string                    // SaaS's IdP client_id
  nonce: string                       // session nonce, also OAuth state=
  poll_token: string                  // pak_/pkr_/pad_ prefix
  client_pubkey: Uint8Array           // 32-byte X25519 public key
  ip_hash: Buffer                     // HMAC-SHA256(ip, internal_secret)
  user_agent: string
  redirect_uri: string                // exact match required for OAuth
  pkce_challenge: string              // base64url(SHA-256(verifier))
  pkce_challenge_method: 'S256'
  intent: 'register' | 'recover' | 'add_key' | 'revalidate'
  target_account_id?: string          // required when intent='recover' or 'revalidate'
}

interface Attestation {
  issuer: string                      // 'github.com'
  subject: string                     // durable upstream ID (numeric)
  audience: string                    // must match context.audience
  expires_at?: Date
  display_handle?: string             // mutable (e.g. GitHub login)
  assurance_level: 'low' | 'medium' | 'high'
  supports_revalidation: boolean
  raw_metadata?: Record<string, unknown>  // provider-specific
}

type ProviderInput =
  | { kind: 'oauth_code', code: string, redirect_uri: string, pkce_verifier: string }
  | { kind: 'attestation_jwt', token: string }
  | { kind: 'api_key', key: string }
  | { kind: 'device_code', device_code: string }

interface IdentityProvider {
  readonly name: string

  /** Phase 1: kick off out-of-band proof gathering. */
  beginRegistration(ctx: AttestationContext): Promise<{
    challenge_url?: string              // browser flow
    deep_link?: string                  // mobile flow
    device_code_info?: {                // device flow
      user_code: string
      verification_uri: string
      verification_uri_complete?: string
      expires_in_seconds: number
      poll_interval_seconds: number
    }
  }>

  /** Phase 2: exchange / verify the proof. Server-side only. */
  exchangeOrVerify(input: ProviderInput, ctx: AttestationContext): Promise<Attestation>

  /** Phase 3: re-verify durable identity (for tier upgrade / periodic check). */
  revalidate(identity: { provider: string; subject: string; audience: string }):
    Promise<{ still_valid: boolean; new_assurance_level?: Attestation['assurance_level'] }>

  /** Phase 4: webhook handler. Verifies HMAC, returns parsed actions. */
  handleWebhook?(headers: Record<string, string>, raw_body: Buffer):
    Promise<{ event_id: string; event_type: string; actions: WebhookAction[] }>
}

type WebhookAction =
  | { type: 'revoke_identity'; subject: string; reason: string }
  | { type: 'flag_identity'; subject: string; signal: string }
```

**Invariants enforced by lib (not provider):**
- `ctx.audience` matches the SaaS's configured IdP client_id
- `ctx.nonce` is single-use (`SELECT FOR UPDATE` + atomic state transition)
- `ctx.client_pubkey` is the 32-byte X25519 key the agent committed to at /begin-registration; cannot change
- `ctx.intent` is immutable once issued; recovery sessions cannot be used as registration sessions
- `Attestation.audience` must equal `ctx.audience` or lib rejects

## 2.2 GitHub App provider (default, primary)

### 2.2.1 Configuration

```typescript
githubApp({
  client_id: 'Iv1.abcdef',                  // GitHub App "client ID" (NOT app_id)
  client_secret: env.GH_CLIENT_SECRET,      // confidential, KMS-managed
  webhook_secret: env.GH_WEBHOOK_SECRET,    // for HMAC-SHA256 verification
  app_private_key_pem: env.GH_APP_PRIVATE_KEY,  // for app JWT (webhook replay polling)
  redirect_uri: 'https://saas.com/api/agent-auth/callback/github_app',
  default_assurance: 'medium',
  use_device_flow: false,                   // browser is default; opt-in for headless
  api_version: '2026-03-10',                // X-GitHub-Api-Version header
  scopes: ['read:user']                     // request minimum
})
```

### 2.2.2 Browser flow (default)

```
[Step 1] Agent → POST /api/agent-auth/begin-registration
  Body: { provider: 'github_app', label?: 'claude-code-laptop',
          client_pubkey: <32 bytes base64url> }

  Lib generates:
    poll_token   = 'pak_' + base64url(randombytes(32))      // 256-bit random
    nonce        = base64url(randombytes(32))               // 256-bit random; OAuth state=
    pkce_verifier = base64url(randombytes(32))              // 256-bit random
    pkce_challenge = base64url(SHA-256(pkce_verifier))      // S256

  INSERT INTO agent_registration_sessions (
    poll_token, nonce, pkce_verifier, pkce_challenge,
    audience='Iv1.abcdef', expected_provider='github_app',
    redirect_uri=<exact_callback_url>, kind='register',
    client_pubkey=<32 bytes>, status='pending',
    expires_at=now()+5min
  )

  Lib calls provider.beginRegistration(ctx) which constructs:
    challenge_url =
      https://github.com/login/oauth/authorize?
        client_id=Iv1.abcdef
        &redirect_uri=https://saas.com/api/agent-auth/callback/github_app
        &state=<nonce>
        &code_challenge=<pkce_challenge>
        &code_challenge_method=S256
        &response_type=code

  Response 200:
    { poll_token: 'pak_...',
      challenge_url: '...',
      expires_at: '2026-04-30T12:05:00Z',
      poll_interval_seconds: 2 }

[Step 2] Agent opens challenge_url in user's browser
  - Agent SDK invokes OS-level open-url, or displays URL for user to copy
  - User authorizes the GitHub App for THIS SaaS only
  - GitHub redirects to redirect_uri with ?code=<auth_code>&state=<nonce>

[Step 3] Lib's GET /api/agent-auth/callback/github_app handler:
  a. SELECT session
       FROM agent_registration_sessions
       WHERE nonce = $state AND status = 'pending' AND expires_at > now()
       FOR UPDATE
     → 400 "registration_session_not_found_or_expired" if no match
        (Do NOT distinguish reasons in error message — anti-enumeration.)

  b. UPDATE session SET status = 'exchanging' WHERE poll_token = $1

  c. provider.exchangeOrVerify({
       kind: 'oauth_code',
       code: $code,
       redirect_uri: session.redirect_uri,
       pkce_verifier: session.pkce_verifier
     }, ctx)
     → calls GitHub:
        POST https://github.com/login/oauth/access_token
        Body: { client_id, client_secret, code, redirect_uri, code_verifier }
     → on success: { access_token, token_type, scope }

     The token is BOUND to this SaaS's client_id by GitHub; another SaaS cannot
     have caused this code to be issued. This is the audience binding.

  d. Lib calls GitHub /user with the access_token:
       Authorization: Bearer <access_token>
       Accept: application/vnd.github+json
       X-GitHub-Api-Version: 2026-03-10
     → returns { id (numeric), login, name, ... }

  e. Lib constructs Attestation:
       { issuer: 'github.com',
         subject: String(user.id),       // durable, numeric
         audience: 'Iv1.abcdef',
         display_handle: user.login,     // mutable, do not key on this
         assurance_level: 'medium',
         supports_revalidation: true }

  f. The access_token is DISCARDED. Lib only stores attestation.subject.

  g. Lib determines flow path:
     - Look up: SELECT * FROM agent_identities
                 WHERE provider='github_app' AND subject=user.id::text
                   AND audience='Iv1.abcdef'
                 FOR UPDATE
     - Case A — no row: NEW account. Create account + identity.
     - Case B — row, status='active': existing account.
                                       This is "additional key" path (is_first_key=false).
     - Case C — row, status='revoked' AND revocation_source IN ('webhook','expiry'):
                If kind='register': REJECT 409 'identity_blocked_use_recover'
                If kind='recover': re-activate (UPDATE status='active', clear revoked_*)
     - Case D — row, status='revoked' AND revocation_source IN ('manual','cascade'):
                REJECT 409 'identity_blocked_admin_unblock_required'

  h. For new key issuance (Case A or B or recovered C):
     - public_id   = base64url(randombytes(6))   // 8 chars, ~48 bits
     - secret      = randombytes(32)             // 256 bits
     - secret_b64  = base64url(secret)           // 43 chars
     - kms_pepper  = await kms.getCurrentPepper()
     - key_hmac    = HMAC-SHA256(kms_pepper, secret)
     - key_id      = 'agk_' + public_id
     - prefix      = secret_b64[:8]              // for display
     INSERT INTO agent_api_keys (
       account_id, issued_via_identity_id,
       key_id, key_hash=key_hmac, prefix,
       label=session.label, scopes=['read', 'self:rotate'],
       version=1, rotation_state='active',
       tier=account.tier, key_pepper_version=kms_pepper.version
     )

  i. Encrypt the key payload to client_pubkey:
     payload = JSON.stringify({
       key: 'agk_<public_id>_<secret_b64>',     // canonical form
       key_id: 'agk_<public_id>',
       account_id, scopes, tier,
       is_first_key: <boolean>,
       issued_at: <iso>
     })
     ciphertext = sodium.crypto_box_seal(payload, session.client_pubkey)
     // Sealed box is anonymous: no sender key needed; only recipient (agent) decrypts

  j. UPDATE agent_registration_sessions
       SET status='ready',
           account_id=<id>,
           result_ciphertext=<ciphertext>
       WHERE poll_token = $1

  k. Render success page in browser (NO secrets in browser):
     "Registration complete. You can return to your agent."

[Step 4] Agent (polling every poll_interval_seconds):
  POST /api/agent-auth/registration-status
  Body: { poll_token: 'pak_...' }

  Lib:
    SELECT * FROM agent_registration_sessions
      WHERE poll_token = $1 AND expires_at > now()
      AND kind IN ('register', 'add_key')
      FOR UPDATE

    Cases:
      - No row found: 410 'session_expired_or_invalid_kind'
      - status='pending' or 'exchanging': 200 { status: 'pending' }
      - status='ready': 200 {
          status: 'completed',
          encrypted_payload: base64url(result_ciphertext)
        }
        // Note: result_ciphertext is NOT cleared. Idempotent retrieval.
        // Cleanup happens via expires_at TTL.
      - status='failed': 200 { status: 'failed', code: 'user_denied' | ... }

[Step 5] Agent decrypts:
  decrypted = sodium.crypto_box_seal_open(
    encrypted_payload, agentKp.publicKey, agentKp.privateKey)
  // Erase agentKp.privateKey via sodium.memzero
  // Store key in agent's secure storage (e.g. macOS Keychain, encrypted file)
```

### 2.2.3 Device flow (alternative, for headless agents)

```
Differences from browser flow:

[Step 1] Agent → POST /begin-registration { provider: 'github_app',
                                             use_device_flow: true,
                                             client_pubkey }
  Lib calls GitHub /login/device/code with client_id (no client_secret in device flow)
  Response includes:
    { device_code, user_code, verification_uri, expires_in, interval }

  Lib stores in agent_device_flows:
    device_code_hash = SHA-256(device_code)
    device_code_encrypted = AES-GCM(device_code, kms_key, iv)
    user_code, verification_uri, expires_at, poll_interval_seconds, status='pending'

  Response 200:
    { poll_token, device_code_info: {
        user_code: 'WDJB-MJHT',
        verification_uri: 'https://github.com/login/device',
        verification_uri_complete: 'https://github.com/login/device?user_code=WDJB-MJHT',
        expires_in_seconds: 900,
        poll_interval_seconds: 5
      } }

[Step 2] Agent shows user the user_code; user visits verification_uri,
  enters code, authorizes app on any browser/device.

[Step 3] Lib background job polls GitHub:
  Every poll_interval_seconds, for sessions with status='pending' AND next_poll_at<=now():
    POST https://github.com/login/oauth/access_token
      Body: { client_id, device_code, grant_type=urn:ietf:params:oauth:grant-type:device_code }
    Cases:
      - 'authorization_pending': UPDATE next_poll_at = now() + poll_interval_seconds
      - 'slow_down': UPDATE poll_interval_seconds += 5
                     UPDATE next_poll_at = now() + new_interval
                     // NOTE: status stays 'pending', NOT 'slow_down'
      - 'expired_token': UPDATE status='expired', mark session 'failed'
      - 'access_denied': UPDATE status='denied', mark session 'failed'
      - success: complete OAuth (same path as browser callback step c-k)

[Step 4] Agent polls /registration-status as in browser flow.
```

### 2.2.4 GitHub webhook handling (`github_app_authorization`)

GitHub fires this event when a user revokes the App's access. Subscribe in GitHub App settings.

```
Endpoint: POST /api/agent-auth/webhooks/github_app
Headers expected:
  Content-Type: application/json
  X-Hub-Signature-256: sha256=<hex>
  X-GitHub-Event: github_app_authorization | other
  X-GitHub-Delivery: <UUID>           // GitHub's delivery ID, idempotency key

Processing order (CRITICAL for security):

  1. Cheap header validation (length, encoding) → reject 400 if malformed
  2. Read raw body (preserve bytes for HMAC)
  3. Verify HMAC-SHA256(body, webhook_secret) == X-Hub-Signature-256
     - Use constant-time compare
     - On fail: 401, do NOT log content, do NOT touch DB
  4. ONLY AFTER VERIFY: parse body JSON, extract event ID
  5. Atomic dedup INSERT:
       INSERT INTO agent_webhook_events (id, provider, event_type, payload_hash, status)
       VALUES ($delivery_id, 'github_app', $event_type, sha256(body), 'received')
       ON CONFLICT (id) DO NOTHING
       RETURNING xmax = 0 AS inserted
     - If inserted=true: continue processing
     - If inserted=false (duplicate):
         SELECT payload_hash FROM agent_webhook_events WHERE id = $1
         IF existing.payload_hash != current_payload_hash:
           LOG ALERT 'webhook_id_collision_with_payload_mismatch'
           // Possible attack: same delivery ID, different body
           // Existing record wins; don't overwrite
         RETURN 200 (already processed)
  6. Process event:
     - github_app_authorization, action='revoked':
         Find: agent_identities WHERE provider='github_app'
                                  AND subject = String(payload.sender.id)
                                  AND audience = configured_client_id
         UPDATE: status='revoked', revoked_at=now(),
                 revoked_reason='user_revoked_app_access',
                 revocation_source='webhook'

         Cascade revoke keys:
           UPDATE agent_api_keys
             SET rotation_state='revoked', revoked_at=now(),
                 revoked_reason='primary_identity_revoked'
             WHERE issued_via_identity_id = identity.id
               AND rotation_state IN ('active', 'rotating')

         Cascade account suspension if no other active primary identities:
           SELECT count(*) FROM agent_identities
             WHERE account_id = identity.account_id
               AND status='active' AND is_primary=true
           IF count = 0:
             UPDATE agent_accounts SET status='suspended', suspended_at=now()
                                       WHERE id = identity.account_id

         Bump revocation epoch:
           UPDATE agent_revocation_epoch SET epoch = epoch + 1, updated_at = now()
           Sync to Redis (Lua MAX): see Section 5.3.2

         Bump revocation barrier (post-commit, see Section 4.4):
           UPDATE agent_revocation_barrier
             SET last_lsn = GREATEST(last_lsn, pg_current_wal_insert_lsn())

         Cache invalidation:
           For each revoked key_id:
             redis.DEL 'agent-auth:key:<key_id>'
             redis.PUBLISH 'agent-auth:invalidate:key:<key_id>'

         Audit: INSERT into agent_audit_log + S3 WORM
  7. UPDATE agent_webhook_events SET status='processed', processed_at=now()
  8. RETURN 200
```

**Replay protection**: even if attacker captures and re-sends a valid webhook, the `agent_webhook_events.id` PRIMARY KEY (PK = X-GitHub-Delivery UUID) ensures idempotent no-op on second delivery. The HMAC is verified BEFORE the dedup INSERT, so attackers cannot poison the dedup table with bogus (id, payload) pairs.

### 2.2.5 Webhook reconciliation (replay missed deliveries)

GitHub does NOT auto-redeliver failed webhooks. Lib polls deliveries within the 3-day window:

```
Background job runs every config.reconciliation.webhook_deliveries_poll_interval_seconds (default 300):

  1. Mint app JWT (RS256 signed with GitHub App private key, 10 min expiry)
  2. Read cursor: agent_webhook_replay_state.last_seen_delivery_id
  3. Loop pages (max config.config_max_pages=10):
     GET https://api.github.com/app/hook/deliveries
       ?per_page=100 [&cursor=<last_seen_id>]
       Headers: Authorization: Bearer <app_jwt>
                Accept: application/vnd.github+json
                X-GitHub-Api-Version: 2026-03-10
  4. For each delivery in page:
     - Skip if delivered_at older than config.config_lookback_hours (default 72)
     - Skip if d.event != 'github_app_authorization'
     - Skip if d.status_code in 200-299 (GitHub thinks it succeeded; trust)
     - Check our local: SELECT status FROM agent_webhook_events WHERE id = d.guid
       - If row exists with status='processed': skip
       - If row exists with status='received'/'failed' OR no row: redeliver
     - POST https://api.github.com/app/hook/deliveries/<d.id>/attempts
       (triggers GitHub to redeliver to our webhook endpoint)
  5. Update cursor: UPDATE agent_webhook_replay_state SET last_seen_delivery_id = first_delivery_in_page
  6. If page count >= max_pages: emit alert metric agent_auth.webhook_replay.cap_hit
  7. Update last_run_status, total_redelivered, last_run_at
```

For longer outages (> 72h), forced fresh OAuth on activity covers it (see Section 2.4).

## 2.3 Other identity providers

### 2.3.1 Anthropic API key (low assurance, secondary use only)

```typescript
anthropicApiKey({
  verify_endpoint: 'https://api.anthropic.com/v1/...',  // verify endpoint TBD
  default_assurance: 'low'
})
```

Cannot be primary identity. Used as secondary proof for tier upgrade. Possession proves payment capability, not stable human identity. Treated as weak signal.

### 2.3.2 Anthropic signed attestation (high assurance, future)

When Anthropic publishes signed attestation standard:

```typescript
anthropicAttestation({
  jwks_url: 'https://anthropic.com/.well-known/jwks.json',
  expected_audience: 'saas-com-prod',
  default_assurance: 'high'
})
```

Lib verifies JWT signature via JWKS. Agent's user-token never reaches lib (Apple Sign In model). Becomes preferred provider once available.

### 2.3.3 Stripe Connect (future, for hot-tier upgrade)

```typescript
stripeConnect({
  account_id: 'acct_...',
  default_assurance: 'high'
})
```

Used as fast-track for hot tier (proves payment + ID verification). Configured per-SaaS.

## 2.4 Forced fresh OAuth revalidation

Default revalidation strategy. Does NOT store user tokens.

```yaml
revalidation:
  policies:
    default:
      cadence_days: 14
      forced_on_webhook_revoke: true
      forced_on_suspicious_activity: true
      forced_on_scim_or_idp_deprovision: true
      forced_on_org_role_or_membership_change: true
    high_risk:                               # admin scopes, hot tier
      cadence_days: 1
      forced_on_password_mfa_passkey_reset: true
      forced_on_privilege_escalation: true
    sensitive_endpoints:                     # per-call revalidation
      revalidate_per_call: true
      endpoints:
        - 'POST /api/agent/v1/admin/*'
        - 'POST /api/agent/v1/transfer/*'
  long_running_agent_checkpoint:
    enabled: true
    revalidate_before_tier_b_actions: true
```

**Trigger**: validation middleware checks `last_revalidated_at`. If older than policy cadence, returns 401 with reauth challenge:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: AgentAuth realm="reauth", reauth_url="https://saas.com/api/agent-auth/begin-registration?intent=revalidate&account_id=<id>"
X-Agent-Auth-Reason: revalidation_required
X-Agent-Auth-Last-Validated: <iso8601>
```

**Agent SDK behavior**: catch 401 with `WWW-Authenticate: AgentAuth realm="reauth"`, run revalidation flow:
1. POST /begin-registration with intent='revalidate', existing_account_id
2. Run OAuth flow (browser or device)
3. Lib's callback verifies code exchange → fresh attestation
4. Lib checks: attestation.subject matches existing identity AND attestation.audience matches config
5. UPDATE last_revalidated_at = now()
6. Token discarded (NOT stored)
7. Original failed validation request retried by SDK with same key

**Why fresh OAuth dance, not just /user fetch**: a new code exchange against THIS SaaS's client_secret proves the user still authorizes the app. A token-call to /user with a stored token only proves the token works (which it would even after app revocation if the token was issued before).

## 2.5 Session lifecycle

```
Registration session states:

  pending ──→ exchanging ──→ ready ──→ (terminal: TTL expiry)
     │            │
     │            └─→ failed (provider error)
     │
     └─→ expired (TTL)
```

**Invariants:**
- `poll_token` is single-use within `kind` namespace; a register-kind token cannot be used as recover-kind (DB-level CHECK + endpoint-level kind filter)
- `client_pubkey` is committed at /begin-registration; cannot be changed mid-flow (RT-20 mitigation)
- `result_ciphertext` is NOT cleared on consumption — sealed-box encryption makes this safe (only agent's private key decrypts)
- Sessions auto-expire 5 minutes after creation; expired sessions are reaped by background job

**Schema:** see Part III §3.5 for full DDL.

## 2.6 Sealed-box payload format

Cleartext (before encryption):
```json
{
  "key": "agk_aB1cD2eF_xK7mN9pQ8rS6tU4vW2xY1zA3bC5dE7fG9hJ0kL2mN4oP6q",
  "key_id": "agk_aB1cD2eF",
  "account_id": "ec5b3df0-7a91-4f7a-b8c2-1d9e2f4a8b6c",
  "scopes": ["read", "self:rotate"],
  "tier": "cold",
  "is_first_key": true,
  "issued_at": "2026-04-30T12:00:00.123Z"
}
```

Encryption: `sodium.crypto_box_seal(plaintext, recipient_pubkey)`
- Uses X25519 + XSalsa20-Poly1305
- Anonymous (no sender keypair needed by recipient to decrypt)
- 48 bytes overhead (32-byte ephemeral pubkey + 16-byte MAC)
- Forward secrecy: even if internal_secret leaks later, sealed boxes from past sessions cannot be decrypted (only the agent's private key, which never left the agent process, can decrypt)

Stored in DB as `result_ciphertext BYTEA`. Idempotent retrieval via /registration-status (no consumption marker).

## 2.7 Rotation

### 2.7.1 Planned rotation (with grace)

```
POST /api/agent-auth/rotate-key
Headers:
  Authorization: Bearer agk_<public_id>_<secret>
  Idempotency-Key: <client-supplied UUID>
Body: { grace_seconds: 3600, reason: 'scheduled_rotation' }

Tier A operation (planned rotations don't need synchronous replication; old key still works during grace).

Server-side, single transaction:

  1. Verify Authorization header → identifies old_key_id, old.account_id
  2. Idempotency check: see Section 5.1
  3. SELECT old.* FROM agent_api_keys
       WHERE id = old.id AND rotation_state = 'active' FOR UPDATE
     → 409 if not active

  4. Generate new key (key_id, key_hash, etc.) as in registration step 2.2.2.h
  5. INSERT new row:
       INSERT INTO agent_api_keys (
         account_id, issued_via_identity_id, key_id, key_hash, prefix,
         label=COALESCE(req.label, old.label),
         scopes=old.scopes, version=1, rotation_state='active',
         tier=old.tier, key_pepper_version=current_pepper.version,
         created_by_key_id=old.id   -- 1:1 inverse, trigger sets old.replaced_by_key_id
       )
     Trigger enforce_rotation_inverse fires:
       UPDATE old SET replaced_by_key_id = new.id WHERE replaced_by_key_id IS NULL
     If 0 rows updated: predecessor already replaced → trigger raises unique_violation
                       (concurrency race resolved deterministically)

  6. UPDATE old:
       SET rotation_state = 'rotating',
           rotated_at = now(),
           rotation_grace_expires_at = now() + grace_seconds * interval '1 second'
     Note: revoked_at remains NULL (CHECK constraint allows: rotating ≠ revoked)

  7. Bump revocation epoch (rotating is auth-relevant):
       UPDATE agent_revocation_epoch SET epoch = epoch + 1
     Update Redis (Lua MAX, Section 5.3.2)

Response 200:
  { old_key: { key_id, rotated_at, grace_expires_at },
    new_key: { key_id, secret, prefix, scopes, tier } }
```

### 2.7.2 Emergency rotation (zero grace)

```
POST /api/agent-auth/rotate-key
Body: { grace_seconds: 0, reason: 'compromised' }

Tier B operation. synchronous_commit = remote_apply.

Single transaction:

  1-5. Same as planned (acquire lock, generate, insert successor)
  6. UPDATE old:
       SET rotation_state = 'revoked',           -- revoked, not rotating
           revoked_at = now(),
           revoked_reason = 'emergency_rotation: <reason>',
           rotated_at = now(),
           rotation_grace_expires_at = now()     -- defensive; immediately expired
     CHECK constraint upheld: rotation_state='revoked' ↔ revoked_at IS NOT NULL

  7. Bump revocation epoch
  8. Capture commit LSN (Section 4.4)
  9. UPDATE agent_revocation_barrier SET last_lsn = GREATEST(last_lsn, commit_lsn)

After commit:

  10. SYNCHRONOUS Redis updates (await all):
        - Lua MAX update of agent-auth:revocation-epoch
        - DEL 'agent-auth:key:<old_key_id>'
        - PUBLISH 'agent-auth:invalidate:key:<old_key_id>'
        - WAIT N replicas, 1000ms — log alert if not all ack
  11. Audit log entry: kind='emergency_rotate'

Response only after Redis updates complete (or timeout with 503).
```

### 2.7.3 Rotation grace expiry

Background job every 60s:
```sql
UPDATE agent_api_keys
SET rotation_state = 'rotated'
WHERE rotation_state = 'rotating'
  AND rotation_grace_expires_at < now();
```

Middleware also auto-transitions on access (lazy):
```typescript
if (cache.rotation_state === 'rotating' && now() >= cache.grace_expires_at) {
  enqueueAsync(() => updateRotatedState(key_id))
  return reject(401, 'rotation_grace_expired')
}
```

## 2.8 Revocation

### 2.8.1 Endpoint

```
POST /api/agent-auth/revoke
Headers:
  Authorization: Bearer <key_with_self:revoke or admin:keys scope>
  Idempotency-Key: <UUID>
Body: { key_id: 'agk_...', reason: 'lost_device' }

Tier B operation. synchronous_commit = remote_apply.
```

### 2.8.2 Server-side flow

```
1. Idempotency check (Section 5.1)
2. Verify caller has scope 'self:revoke' (if revoking own key) or 'admin:keys'
3. Single transaction with synchronous_commit=remote_apply:

   SELECT * FROM agent_api_keys WHERE key_id = $key_id FOR UPDATE
   → 404 if not found, 409 if already revoked (with idempotent response)

   UPDATE agent_api_keys
     SET rotation_state = 'revoked',
         revoked_at = now(),
         revoked_reason = $reason
     WHERE id = $id

   UPDATE agent_revocation_epoch SET epoch = epoch + 1, updated_at = now()
     -- Captures the new global epoch

   Capture commit LSN: SELECT pg_current_wal_insert_lsn()

   UPDATE agent_revocation_barrier
     SET last_lsn = GREATEST(last_lsn, $commit_lsn),
         updated_at = now()
     WHERE id = 1

   INSERT INTO agent_revocation_log (
     ts, region, kind, target_id, commit_lsn, reason, epoch
   )

4. Wait for synchronous standby ack (handled by synchronous_commit setting)
   - Timeout: 5 seconds (config.tier_b_commit_timeout_ms)
   - On timeout: idempotency row marked 'unknown'; return 503 'durability_unconfirmed'

5. Post-commit Redis updates:
   redis.eval(EPOCH_UPDATE_SCRIPT, 1, 'agent-auth:revocation-epoch', new_epoch)
   redis.del('agent-auth:key:<key_id>')
   redis.publish('agent-auth:invalidate:key:<key_id>', '1')
   redis.wait(replica_quorum, 1000ms)  -- log warn if not all ack

6. Audit log: external WORM + in-DB hash chain (see Section 6.4)

Response 200: { revoked_at: <iso>, key_id: 'agk_...' }
```

### 2.8.3 Validation guarantee

After /revoke returns 200, ANY validation request observes the key as revoked. Holds because:
- Tier B sync commit ensures Postgres state is durably replicated
- Cache validation always checks epoch; mismatch forces Postgres re-read
- If Redis unreachable: validation falls through to Postgres directly
- If Postgres unreachable: lib fails closed (503)

## 2.9 Recovery

Recovery is a separate flow with its own poll-token namespace (`pkr_` prefix).

```
1. POST /api/agent-auth/begin-registration
   Body: { intent: 'recover', account_id: <id_to_recover>,
           provider: 'github_app', client_pubkey: <32 bytes> }

   Lib generates poll_token with 'pkr_' prefix.
   INSERT session with kind='recover', target_account_id = $account_id

   Validate at this step:
     SELECT * FROM agent_accounts WHERE id = $account_id
     IF status = 'closed': REJECT 410 'account_closed'
     IF status = 'suspended': REJECT 403 'account_suspended_unsuspend_first'
     IF status != 'active': REJECT 500 'unknown_account_status' (fail-closed)

2. User completes fresh OAuth (browser or device)

3. /callback verifies code exchange, gets attestation
4. Lib looks up identity matching (provider, subject, audience):
   IF identity not found: REJECT 403 'identity_not_recognized_for_account'
   IF identity.account_id != session.target_account_id:
     REJECT 403 'identity_account_mismatch'
   IF !canReactivateIdentity(identity.status, identity.revocation_source):
     REJECT 409 'identity_blocked'

5. Owner approval webhook (if configured):
   POST <approval_webhook_url>
   Headers: X-Agent-Auth-Signature (HMAC over canonical),
            X-Agent-Auth-Timestamp, X-Agent-Auth-Nonce, X-Agent-Auth-Request-Id
   Body: { request_id, account_id, identity_subject, approval_callback_url, expires_at }

   Wait for approval (default 24h).

6. After approval (or if not required):
   IF identity.status = 'revoked':
     UPDATE: status='active', revoked_at=NULL, revoked_reason=NULL,
             revocation_source=NULL, last_revalidated_at=now()
   Issue NEW key (issued_via_identity_id = identity.id)
   Old keys stay revoked (do not resurrect)

7. Encrypt to client_pubkey, store in result_ciphertext, status='ready'

8. Agent polls /api/agent-auth/recover-account-status (with pkr_ poll_token)
   Returns encrypted_payload as in registration.
```


---

# Part III — Data Layer

This section is the authoritative DDL. SQL is PostgreSQL 14+. Schema versioning by `schema/migrations/NNNN_*.sql` files.

## 3.1 Schema overview

```
agent_accounts                     1 row per logical account
  └─ agent_identities              0..N upstream identity bindings per account
       └─ agent_api_keys           0..N keys, each issued via a specific identity
agent_registration_sessions        ephemeral, 5-min TTL
agent_device_flows                 ephemeral, OAuth device flow polling state
agent_audit_log                    partitioned by day, hash-chained
agent_webhook_events               idempotency for upstream webhooks
agent_webhook_replay_state         per-provider cursor for reconciliation
agent_revocation_log               cross-region replicated, append-only
agent_revocation_epoch             singleton, monotonic counter
agent_revocation_barrier           singleton, post-commit LSN watermark
agent_idempotency                  Tier B operation idempotency
agent_recovery_approvals           recovery webhook state
agent_jobs                         internal background queue
```

## 3.2 Type domains

```sql
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
```

## 3.3 agent_accounts

```sql
CREATE TABLE agent_accounts (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  display_handle      TEXT,                  -- denormalized for UX
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

CREATE INDEX agent_accounts_status_active
  ON agent_accounts(status) WHERE status = 'active';

CREATE INDEX agent_accounts_tier
  ON agent_accounts(tier) WHERE status = 'active';

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION trigger_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_accounts_updated_at
  BEFORE UPDATE ON agent_accounts
  FOR EACH ROW EXECUTE FUNCTION trigger_set_updated_at();
```

## 3.4 agent_identities

```sql
CREATE TABLE agent_identities (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id          UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  provider            TEXT NOT NULL,           -- 'github_app' | 'anthropic_attestation' | ...
  subject             TEXT NOT NULL,           -- durable upstream ID (numeric for GitHub)
  audience            TEXT NOT NULL,           -- this SaaS's IdP client_id
  issuer              TEXT NOT NULL,           -- 'github.com' | 'anthropic.com' | ...
  assurance_level     assurance_level_enum NOT NULL,
  display_handle      TEXT,                    -- mutable; do not key on this
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

CREATE UNIQUE INDEX agent_identities_unique_active
  ON agent_identities(provider, subject, audience);

CREATE UNIQUE INDEX agent_identities_one_primary_per_account
  ON agent_identities(account_id) WHERE is_primary AND status = 'active';

CREATE INDEX agent_identities_account_active
  ON agent_identities(account_id) WHERE status = 'active';
```

## 3.5 agent_api_keys

```sql
CREATE TABLE agent_api_keys (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id                  UUID NOT NULL REFERENCES agent_accounts(id) ON DELETE CASCADE,
  issued_via_identity_id      UUID NOT NULL REFERENCES agent_identities(id),
  key_id                      TEXT NOT NULL UNIQUE,        -- 'agk_<8 chars>'
  key_hash                    BYTEA NOT NULL,              -- HMAC-SHA256(secret, kms_pepper)
  key_pepper_version          INT NOT NULL DEFAULT 1,
  prefix                      TEXT NOT NULL,               -- secret[:8] for display
  label                       TEXT,                        -- e.g. 'claude-code-laptop'
  scopes                      TEXT[] NOT NULL DEFAULT '{}',
  tier                        tier_enum NOT NULL DEFAULT 'cold',
  version                     INT NOT NULL DEFAULT 1,      -- bumped on cache-affecting changes
  expires_at                  TIMESTAMPTZ,
  last_used_at                TIMESTAMPTZ,
  rotation_state              rotation_state_enum NOT NULL DEFAULT 'active',
  rotated_at                  TIMESTAMPTZ,
  rotation_grace_expires_at   TIMESTAMPTZ,
  replaced_by_key_id          UUID REFERENCES agent_api_keys(id),
  created_by_key_id           UUID REFERENCES agent_api_keys(id),
  revoked_at                  TIMESTAMPTZ,
  revoked_reason              TEXT,
  last_revoke_lsn             pg_lsn,                      -- optimization, not correctness gate
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

-- Active keys lookup for hot path validation
CREATE INDEX agent_api_keys_active_lookup
  ON agent_api_keys(key_id)
  WHERE rotation_state IN ('active', 'rotating');

-- One predecessor per new key
CREATE UNIQUE INDEX agent_api_keys_one_predecessor
  ON agent_api_keys(created_by_key_id)
  WHERE created_by_key_id IS NOT NULL;

-- One successor per old key
CREATE UNIQUE INDEX agent_api_keys_one_successor
  ON agent_api_keys(replaced_by_key_id)
  WHERE replaced_by_key_id IS NOT NULL;

CREATE INDEX agent_api_keys_account ON agent_api_keys(account_id);
CREATE INDEX agent_api_keys_identity ON agent_api_keys(issued_via_identity_id);

COMMENT ON COLUMN agent_api_keys.last_revoke_lsn IS
  'Optimization: per-key barrier. NOT a correctness gate.
   Correctness uses agent_revocation_barrier.last_lsn (global authoritative).';

-- Trigger: enforce 1:1 inverse on rotation
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

CREATE TRIGGER trigger_enforce_rotation_inverse
  AFTER INSERT ON agent_api_keys
  FOR EACH ROW EXECUTE FUNCTION enforce_rotation_inverse();

-- Trigger: sync account.tier → keys.tier on tier change
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

CREATE TRIGGER trigger_sync_account_tier
  AFTER UPDATE OF tier ON agent_accounts
  FOR EACH ROW
  WHEN (OLD.tier IS DISTINCT FROM NEW.tier)
  EXECUTE FUNCTION sync_account_tier_to_keys();
```

## 3.6 agent_registration_sessions

```sql
CREATE TABLE agent_registration_sessions (
  poll_token         TEXT PRIMARY KEY,
  nonce              TEXT NOT NULL UNIQUE,
  pkce_verifier      TEXT NOT NULL,
  pkce_challenge     TEXT NOT NULL,
  audience           TEXT NOT NULL,
  expected_provider  TEXT NOT NULL,
  redirect_uri       TEXT NOT NULL,
  kind               session_kind_enum NOT NULL,
  target_account_id  UUID REFERENCES agent_accounts(id),
  client_pubkey      BYTEA NOT NULL,             -- 32 bytes X25519
  status             session_status_enum NOT NULL DEFAULT 'pending',
  status_message     TEXT,
  result_ciphertext  BYTEA,                      -- sealed-box encrypted
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

CREATE INDEX agent_reg_sessions_active
  ON agent_registration_sessions(expires_at)
  WHERE status IN ('pending', 'ready');

-- Background reaper job runs every minute
-- DELETE FROM agent_registration_sessions WHERE expires_at < now() - interval '1 hour';
```

## 3.7 agent_device_flows

```sql
CREATE TABLE agent_device_flows (
  device_code_hash       BYTEA PRIMARY KEY,    -- SHA-256 of device_code
  device_code_encrypted  BYTEA NOT NULL,       -- AES-GCM encrypted device_code
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

CREATE INDEX agent_device_flows_polling
  ON agent_device_flows(next_poll_at, status)
  WHERE status = 'pending';
```

## 3.8 agent_audit_log (partitioned, hash-chained)

```sql
CREATE TABLE agent_audit_log (
  id           BIGSERIAL,
  ts           TIMESTAMPTZ NOT NULL,
  account_id   UUID,
  key_id       TEXT,
  identity_id  UUID,
  event_type   TEXT NOT NULL,
  endpoint     TEXT,
  ip_hash      BYTEA,                           -- HMAC-SHA256(ip, internal_secret)
  asn          INT,
  user_agent   TEXT,                            -- truncated/scrubbed
  status_class INT,                             -- 2 / 3 / 4 / 5
  cost_units   INT NOT NULL DEFAULT 1,
  meta         JSONB,                           -- scrubbed by lib (Section 6.6)
  prev_hash    BYTEA,                           -- previous row's row_hash
  row_hash     BYTEA,                           -- SHA-256(prev_hash || canonical(this row))
  PRIMARY KEY (id, ts)
) PARTITION BY RANGE (ts);

-- Daily partitions managed by lib's scheduled job (Section 8.2.2)
CREATE INDEX agent_audit_account_ts ON agent_audit_log USING BRIN (account_id, ts);
CREATE INDEX agent_audit_key_ts ON agent_audit_log USING BRIN (key_id, ts);
CREATE INDEX agent_audit_event_ts ON agent_audit_log USING BRIN (event_type, ts);

-- Permissions: append-only by app role
-- (app role gets INSERT only; UPDATE/DELETE require admin role)

-- Hash chain trigger
CREATE OR REPLACE FUNCTION compute_audit_row_hash() RETURNS TRIGGER AS $$
DECLARE
  prev BYTEA;
  canonical TEXT;
BEGIN
  -- Get previous row's hash from same partition (or 0x00...0 for first row of day)
  SELECT row_hash INTO prev FROM agent_audit_log
    WHERE ts >= date_trunc('day', NEW.ts)
    ORDER BY id DESC LIMIT 1;
  IF prev IS NULL THEN
    prev = decode('0000000000000000000000000000000000000000000000000000000000000000', 'hex');
  END IF;

  NEW.prev_hash = prev;

  -- Canonical form: sorted keys, fixed format
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

CREATE TRIGGER trigger_audit_hash_chain
  BEFORE INSERT ON agent_audit_log
  FOR EACH ROW EXECUTE FUNCTION compute_audit_row_hash();
```

## 3.9 agent_webhook_events

```sql
CREATE TABLE agent_webhook_events (
  id            UUID PRIMARY KEY,                  -- X-GitHub-Delivery
  provider      TEXT NOT NULL,
  event_type    TEXT NOT NULL,
  payload_hash  BYTEA NOT NULL,                    -- SHA-256 of body
  received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at  TIMESTAMPTZ,
  status        TEXT NOT NULL DEFAULT 'received'
                CHECK (status IN ('received', 'processed', 'failed', 'ignored')),
  error         TEXT,
  payload_snippet JSONB                            -- first 1KB, scrubbed; for debugging
);

CREATE INDEX agent_webhook_events_unprocessed
  ON agent_webhook_events(received_at)
  WHERE status IN ('received', 'failed');

CREATE INDEX agent_webhook_events_provider_received
  ON agent_webhook_events(provider, received_at);
```

## 3.10 agent_webhook_replay_state

```sql
CREATE TABLE agent_webhook_replay_state (
  provider                       TEXT PRIMARY KEY,
  last_seen_delivery_id          TEXT,
  last_run_at                    TIMESTAMPTZ,
  last_run_status                TEXT
                                  CHECK (last_run_status IN ('ok','partial','failed','cap_hit')),
  catch_up_pages                 INT NOT NULL DEFAULT 0,
  total_redelivered              BIGINT NOT NULL DEFAULT 0,
  config_max_pages               INT NOT NULL DEFAULT 10,
  config_lookback_hours          INT NOT NULL DEFAULT 72,    -- GitHub limit
  config_poll_interval_seconds   INT NOT NULL DEFAULT 300
);

INSERT INTO agent_webhook_replay_state (provider) VALUES ('github_app');
```

## 3.11 agent_revocation_log

```sql
CREATE TABLE agent_revocation_log (
  id                       BIGSERIAL PRIMARY KEY,
  ts                       TIMESTAMPTZ NOT NULL DEFAULT now(),
  region                   TEXT NOT NULL,
  kind                     TEXT NOT NULL
                           CHECK (kind IN ('key_revoke', 'account_suspend',
                                           'identity_revoke', 'emergency_rotate',
                                           'account_close')),
  target_id                TEXT NOT NULL,
  commit_lsn               pg_lsn NOT NULL,           -- captured post-commit
  epoch                    BIGINT NOT NULL,           -- global revocation_epoch at time
  reason                   TEXT,
  replicated_to_regions    TEXT[]
);

CREATE INDEX agent_revocation_log_lsn ON agent_revocation_log(commit_lsn);
CREATE INDEX agent_revocation_log_target ON agent_revocation_log(target_id);
```

## 3.12 Singletons: epoch and barrier

```sql
CREATE TABLE agent_revocation_epoch (
  id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  epoch       BIGINT NOT NULL DEFAULT 0,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO agent_revocation_epoch (id, epoch) VALUES (1, 0);

CREATE TABLE agent_revocation_barrier (
  id          INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_lsn    pg_lsn NOT NULL,
  timeline_id INT NOT NULL DEFAULT 1,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO agent_revocation_barrier (id, last_lsn, timeline_id) VALUES (1, '0/0', 1);
```

## 3.13 agent_idempotency

```sql
CREATE TABLE agent_idempotency (
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

CREATE INDEX agent_idempotency_state ON agent_idempotency(state)
  WHERE state IN ('pending', 'unknown');
CREATE INDEX agent_idempotency_expires ON agent_idempotency(expires_at);

-- Trigger: monotonic state transitions
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
    INSERT INTO agent_audit_log (ts, event_type, meta)
    VALUES (now(), 'idempotency_admin_override',
            jsonb_build_object('key', NEW.key, 'from', OLD.state, 'to', NEW.state));
    allowed := true;
  END IF;

  IF NOT allowed THEN
    RAISE EXCEPTION 'idempotency_invalid_transition: % → %', OLD.state, NEW.state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_idempotency_transitions
  BEFORE UPDATE OF state ON agent_idempotency
  FOR EACH ROW EXECUTE FUNCTION enforce_idempotency_transitions();

-- Trigger: terminal row immutability (outside `state`)
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

CREATE TRIGGER trigger_idempotency_terminal_immutable
  BEFORE UPDATE ON agent_idempotency
  FOR EACH ROW EXECUTE FUNCTION enforce_terminal_row_immutable();
```

## 3.14 agent_recovery_approvals

```sql
CREATE TABLE agent_recovery_approvals (
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

CREATE INDEX agent_recovery_approvals_pending
  ON agent_recovery_approvals(expires_at)
  WHERE decision IS NULL OR decision = 'pending';
```

## 3.15 agent_jobs (internal queue)

```sql
CREATE TABLE agent_jobs (
  id           BIGSERIAL PRIMARY KEY,
  kind         TEXT NOT NULL,                -- 'cache_invalidate_keys' | 'reconcile_idempotency' | ...
  payload      JSONB NOT NULL,
  run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  attempts     INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 5,
  status       TEXT NOT NULL DEFAULT 'pending'
               CHECK (status IN ('pending', 'running', 'completed', 'failed', 'dead')),
  last_error   TEXT,
  locked_at    TIMESTAMPTZ,
  locked_by    TEXT,                         -- worker hostname/pid
  completed_at TIMESTAMPTZ
);

CREATE INDEX agent_jobs_runnable
  ON agent_jobs(run_at, kind)
  WHERE status = 'pending';

CREATE INDEX agent_jobs_stuck
  ON agent_jobs(locked_at)
  WHERE status = 'running';
```

## 3.16 Database roles

```sql
-- Application role (pooled connections use this)
CREATE ROLE agent_auth_app NOLOGIN;
GRANT USAGE ON SCHEMA public TO agent_auth_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO agent_auth_app;
-- Audit log: INSERT only, no UPDATE/DELETE
REVOKE UPDATE, DELETE ON agent_audit_log FROM agent_auth_app;

-- Admin role (separate connection, MFA-gated, audit-logged)
CREATE ROLE agent_auth_admin NOLOGIN;
GRANT USAGE ON SCHEMA public TO agent_auth_admin;
GRANT INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agent_auth_admin;

-- Read-only role for analysts/reporting
CREATE ROLE agent_auth_readonly NOLOGIN;
GRANT USAGE ON SCHEMA public TO agent_auth_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_auth_readonly;
-- But cannot read audit_log meta (configurable)
REVOKE SELECT ON agent_audit_log FROM agent_auth_readonly;
GRANT SELECT (id, ts, event_type, account_id, key_id, status_class)
  ON agent_audit_log TO agent_auth_readonly;
```

## 3.17 Migration policy

- All migrations live in `schema/migrations/NNNN_description.sql`
- NNNN is monotonic
- Each migration has a corresponding `NNNN_description.down.sql` rollback
- Migrations are forward-compatible: lib version N must be able to read schema N+1
- Destructive changes (DROP COLUMN, ALTER TYPE) require:
  - Feature flag gating
  - Two-deploy migration: read-both-old-and-new period
  - Lib version bump in same release
- Migrations are idempotent: re-running has no effect
- Migrations test on copy of prod data shape before prod deploy


---

# Part IV — Distributed System Design

## 4.1 Topology choices

### 4.1.1 Single-region (default for v0.1)

```
┌─────────────────────────────────────────────────────────┐
│ Region: us-east-1                                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐         │
│  │ App pod 1  │  │ App pod 2  │  │ App pod N  │         │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘         │
│        │               │               │                │
│        └───────────────┴───────────────┘                │
│                       │                                 │
│              ┌────────┴────────┐                        │
│              │                 │                        │
│        ┌─────▼─────┐    ┌─────▼─────┐                  │
│        │ Postgres  │    │   Redis   │                  │
│        │ primary   │    │ primary   │                  │
│        └─────┬─────┘    └─────┬─────┘                  │
│              │                │                        │
│        ┌─────▼─────┐    ┌─────▼─────┐                  │
│        │ Postgres  │    │   Redis   │                  │
│        │ standby   │    │ replica   │                  │
│        │ (sync)    │    │           │                  │
│        └───────────┘    └───────────┘                  │
└─────────────────────────────────────────────────────────┘
              │
              ▼
       S3 Object Lock
       (different account)
```

Postgres synchronous standby in same region (different AZ) for Tier B durability. Redis replica for high availability + WAIT command quorum.

### 4.1.2 Multi-region active-passive (optional, for global SaaS)

```
Primary region: us-east-1
  - Writes: registration, rotation, revocation, account ops
  - Reads: validation (with cache)

Secondary regions: us-west-2, eu-west-1
  - Reads only
  - Validation falls through to primary on:
    - Cache miss after epoch mismatch
    - Replica lag > threshold (LSN comparison)
    - Timeline mismatch
```

Cross-region replication via PostgreSQL streaming replication. Synchronous standbys in primary region. Async replicas in secondary regions.

Validation in secondary region requires authoritative barrier read from primary (Section 4.4).

### 4.1.3 Active-active (deferred to v0.2+)

Active-active with 1s revocation freshness requires:
- Cross-region revocation log replicated synchronously (quorum)
- Or validation routes to primary for any revocation-relevant decision

Out of scope for v0.1.

## 4.2 Durability tier classification

Every operation is classified at design time:

| Operation | Tier | Sync replication | Idempotency required |
|---|---|---|---|
| Account create | A | Async streaming | Optional |
| Account update (display, etc.) | A | Async streaming | Optional |
| Identity create | A | Async streaming | Optional |
| Key issue (planned, first or rotation) | A | Async streaming | Optional |
| Key rotate (planned, grace > 0) | A | Async streaming | Required |
| **Key rotate (emergency, grace = 0)** | **B** | Sync (remote_apply) | Required |
| **Key revoke (any reason)** | **B** | Sync (remote_apply) | Required |
| **Account suspend** | **B** | Sync (remote_apply) | Required |
| **Account close** | **B** | Sync (remote_apply) | Required |
| **Account erase (cascade revokes)** | **B** | Sync (remote_apply) | Required |
| **Identity revoke (cascade keys)** | **B** | Sync (remote_apply) | Required |
| Validation (read-only) | A | Read replica OK | N/A |
| Webhook receipt | A | Async OK (idempotent) | Built-in (delivery_id) |
| Audit log | A | Async + WORM external | N/A |

### 4.2.1 Tier A semantics

```sql
SET LOCAL synchronous_commit = on;  -- default
-- 5-min RPO, replication is asynchronous streaming
-- On primary failover: lag-bounded data loss possible
```

### 4.2.2 Tier B semantics

```sql
SET LOCAL synchronous_commit = remote_apply;
-- Standby must apply WAL before primary acks
-- 0 RPO for confirmed writes
-- On standby unreachable: write blocks until config.tier_b_commit_timeout_ms
-- On timeout: client receives 503 'durability_unconfirmed'
```

## 4.3 Tier B commit timeout handling

```typescript
async function tierBCommit<T>(operation: () => Promise<T>): Promise<T> {
  const COMMIT_TIMEOUT_MS = config.tier_b_commit_timeout_ms ?? 5000;

  let timeoutHandle: NodeJS.Timeout;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(() => reject(new TierBTimeoutError()), COMMIT_TIMEOUT_MS);
  });

  try {
    return await Promise.race([operation(), timeoutPromise]);
  } catch (err) {
    if (err instanceof TierBTimeoutError) {
      // Outcome unknown: commit may have succeeded on primary but standby
      // ack lost. Idempotency observer reconciles via resource_ref lookup.
      log.alert('tier_b_unknown_outcome', { opName: operation.name });
      metrics.increment('agent_auth.tier_b.unknown_outcome');
      throw new ServiceUnavailableError('durability_unconfirmed', {
        retry_with: getIdempotencyKey()
      });
    }
    if (err.code === 'XX098' /* postgres synchronous_commit failed */) {
      log.alert('tier_b_standby_unreachable');
      metrics.increment('agent_auth.tier_b.standby_unreachable');
      throw new ServiceUnavailableError('durability_unavailable');
    }
    throw err;
  } finally {
    clearTimeout(timeoutHandle);
  }
}
```

Operator runbook: investigation procedure for `tier_b.unknown_outcome` alerts (RB-3).

## 4.4 LSN barrier protocol (multi-region correctness)

### 4.4.1 The problem

In an active-passive multi-region deployment, secondary regions serve validation reads from local async replicas. A revocation committed on primary at time T may not be visible in secondary until replication catches up. Without barriers, a key validated in secondary could be accepted when it has been revoked.

### 4.4.2 The protocol

```
Write path (revocation):
  1. Tier B transaction commits on primary with synchronous_commit=remote_apply
     (sync standby in primary region acks; WAL is durable)
  2. Lib captures commit_lsn := pg_current_wal_insert_lsn() (post-commit)
  3. Lib UPDATEs agent_revocation_barrier:
       UPDATE agent_revocation_barrier
         SET last_lsn = GREATEST(last_lsn, $commit_lsn),
             updated_at = now()
         WHERE id = 1
     (also Tier B sync committed)
  4. Lib INSERTs agent_revocation_log with commit_lsn
  5. /revoke API returns 200 to caller (revocation is now durably acked)

Read path (validation in secondary region):
  1. App reads authoritative barrier from PRIMARY DB:
       authoritativeBarrier = await primaryDb.queryOne(
         'SELECT last_lsn, timeline_id FROM agent_revocation_barrier WHERE id=1'
       )
     (NOT from secondary's local copy — that may be stale)
     Cached locally only in `strict_uncached` mode = NO cache
                          in `bounded_stale_1s` mode = 1-second cache

  2. Read local replica's replay position:
       replayPos = await localDb.queryOne('SELECT pg_last_wal_replay_lsn() AS lsn')

  3. Determine role:
       inRecovery = await localDb.queryOne('SELECT pg_is_in_recovery() AS ir')
     (NOT pg_last_wal_replay_lsn() IS NULL — that's unreliable)

     If !inRecovery (we're primary): direct local read trusted, skip barrier check.
     If inRecovery: continue.

  4. Check timeline:
       localTimeline = (SELECT timeline_id FROM pg_control_checkpoint())
       IF localTimeline != authoritativeBarrier.timeline_id:
         REJECT 503 'failover_in_progress'
         (Operator runs RB-8 to reset barrier on new timeline.)

  5. Correctness gate:
       IF pg_lsn_compare(replayPos.lsn, authoritativeBarrier.last_lsn) < 0:
         IF config.on_lag = 'fail_closed':
           REJECT 503 'region_replication_stale'
         ELSE IF config.on_lag = 'route_to_primary':
           return await primaryDb.validate(keyId)

  6. Local replica is sufficiently caught up. Trust local read for this key.
     return await standardValidationViaLocalDb(keyId)
```

### 4.4.3 Why this is correct

**Claim**: any validation request that arrives after /revoke returned 200 sees the key as revoked.

**Proof sketch**:
- /revoke does not return 200 until step 4 (UPDATE barrier) is in committed WAL
- The barrier update is in WAL position L_b (some LSN)
- Validation in secondary reads `last_lsn` from primary, observes L_b
- If local replica's replay position L_local < L_b, validation refuses (route or fail-closed)
- If L_local >= L_b, replica has applied all WAL up to and including the revoke
- Therefore validation reads the post-revoke key state

**Caveat**: requires the barrier read to come from primary, not local replica. If config uses `bounded_stale_1s`, this property holds within 1-second staleness window post-revoke (documented compromise).

### 4.4.4 Failover handling

When primary fails and a standby is promoted:
- Timeline ID changes (Postgres timeline)
- New primary's `pg_current_wal_insert_lsn()` starts on new timeline
- Old barrier value's timeline_id no longer matches

App readiness gate (K8s readiness probe):
```bash
#!/bin/bash
# scripts/agent-auth/post-promotion-reset.sh
set -euo pipefail

# Capture fresh barrier on new primary
NEW_LSN=$(psql -tAc "SELECT pg_current_wal_insert_lsn()")
NEW_TIMELINE=$(psql -tAc "SELECT timeline_id FROM pg_control_checkpoint()")

psql <<SQL
UPDATE agent_revocation_barrier
SET last_lsn = '$NEW_LSN'::pg_lsn,
    timeline_id = $NEW_TIMELINE,
    updated_at = now();
SQL

# Flush Redis caches
redis-cli FLUSHDB

# Emit promotion event to audit
psql <<SQL
INSERT INTO agent_audit_log (ts, event_type, meta)
VALUES (now(), 'promotion_completed',
        jsonb_build_object('new_timeline', $NEW_TIMELINE,
                          'new_barrier_lsn', '$NEW_LSN'));
SQL

# Touch readiness file
touch /var/lib/agent-auth/ready
```

App's readiness probe checks for `/var/lib/agent-auth/ready`. Until present, K8s does not route traffic.

## 4.5 Replication tier matrix (multi-region)

When multi-region is enabled:

| Operation | Primary commit | Same-region sync standby | Cross-region async replicas |
|---|---|---|---|
| Tier A | Required | Required | Eventually consistent |
| Tier B | Required | Required (synchronous_commit=remote_apply) | Eventually consistent + LSN barrier check on validation |

**Validation correctness in secondary region**: enforced by LSN barrier protocol (Section 4.4).

**Cross-region revocation log**: agent_revocation_log is replicated via streaming. Secondary regions can query it locally for forensic / metric purposes. For correctness, only barrier matters.

## 4.6 Failure mode summary

| Failure | Effect | Mitigation |
|---|---|---|
| Primary Postgres down | All writes fail | Failover to sync standby (RTO < 1 min) + RB-8 |
| Sync standby down | Tier B writes return 503 | Operator alert; promote async standby to sync (RB-3) |
| Async replica down (secondary region) | Local validation falls back to primary | Per-region monitoring; auto-disable failing region |
| Redis primary down | Cache miss → Postgres direct (degraded perf) | Failover to Redis replica via Sentinel |
| Redis network partition | Cache writes may be lost | TTL-bounded staleness; pubsub may not reach all subs |
| KMS unreachable | New key issuance blocked; existing validations OK (HMAC pepper cached) | Operator alert; ops continue with cached pepper |
| S3 (audit WORM) unreachable | Tier B operations fail (durability requirement) | Outbox pattern; alert; resume after recovery |
| Cross-region replication broken | Secondary regions fail closed on validation (LSN barrier) | Auto-detect + alert; remove region from LB |


---

# Part V — Reliability Engineering

## 5.1 Idempotency framework

### 5.1.1 Two-phase reservation

Every Tier B write (revoke, emergency rotate, suspend, close, erase) requires `Idempotency-Key` header. Lib enforces idempotency via two-phase pattern:

**Phase 1**: Reserve idempotency row in own transaction
**Phase 2**: Execute operation in Tier B transaction
**Phase 3**: Background reconciliation observer for unknown outcomes

```typescript
async function tierBIdempotent<T>(
  idemKey: string,
  requestHash: Buffer,
  operationType: string,         // 'revoke' | 'rotate_emergency' | 'suspend_account' | ...
  resourceRef: string,           // 'key:agk_aB1cD2eF' | 'rotation:agk_xxx' | 'account:<uuid>'
  operation: (tx: DBTransaction) => Promise<{ status: number; body: T }>
): Promise<{ status: number; body: T }> {

  // PHASE 1: durable reservation (own transaction, NOT the Tier B tx)
  const reserved = await db.transaction(async (tx) => {
    const existing = await tx.queryOne(
      `SELECT * FROM agent_idempotency WHERE key = $1 FOR UPDATE`,
      [idemKey]
    );

    if (existing) {
      if (!constantTimeEqual(existing.request_hash, requestHash)) {
        throw new IdempotencyMismatchError(409, 'idempotency_key_payload_mismatch');
      }
      return existing;  // resume from existing row
    }

    await tx.query(
      `INSERT INTO agent_idempotency
       (key, request_hash, operation_type, resource_ref, state, expires_at)
       VALUES ($1, $2, $3, $4, 'pending', now() + interval '24 hours')`,
      [idemKey, requestHash, operationType, resourceRef]
    );
    return null;  // newly created
  });

  // Resume cases:
  if (reserved?.state === 'completed') {
    return { status: reserved.outcome_status, body: reserved.outcome_body };
  }
  if (reserved?.state === 'failed') {
    throw new BusinessError(reserved.outcome_status, reserved.outcome_body);
  }
  if (reserved?.state === 'pending') {
    // Concurrent retry: original is still in flight
    throw new TooEarlyError(425, 'idempotency_in_flight', { retry_after: 1 });
  }
  if (reserved?.state === 'unknown') {
    throw new ServiceUnavailableError(503, 'idempotency_unknown_outcome');
  }
  if (reserved?.state === 'manual_required') {
    throw new ServiceUnavailableError(503, 'idempotency_manual_required');
  }

  // PHASE 2: actual operation in Tier B transaction
  let result: { status: number; body: T };
  try {
    result = await tierBCommit(() => db.transaction(operation));

    // Mark completed (transition pending → completed)
    await db.query(
      `UPDATE agent_idempotency
       SET state='completed', outcome_status=$2, outcome_body=$3
       WHERE key=$1`,
      [idemKey, result.status, result.body]
    );
  } catch (err) {
    if (err instanceof TierBTimeoutError) {
      // Outcome unknown: observer will reconcile
      await db.query(
        `UPDATE agent_idempotency SET state='unknown' WHERE key=$1`,
        [idemKey]
      );
      throw err;  // 503 to caller
    }
    if (err instanceof BusinessError) {
      // Terminal business failure
      await db.query(
        `UPDATE agent_idempotency SET state='failed', outcome_status=$2, outcome_body=$3
         WHERE key=$1`,
        [idemKey, err.status, err.body]
      );
    }
    throw err;
  }

  return result;
}
```

### 5.1.2 Reconciliation observer

Background job runs every 60 seconds:

```typescript
async function reconcileUnknownIdempotency() {
  const stale = await db.query(
    `SELECT * FROM agent_idempotency
     WHERE state IN ('pending', 'unknown')
       AND created_at < now() - interval '5 minutes'
     ORDER BY created_at ASC
     LIMIT 100`
  );

  for (const row of stale.rows) {
    // Promote to manual_required after 5 attempts or 30 min
    const tooManyAttempts = row.reconcile_attempts >= 5;
    const tooOld = row.last_reconcile_at &&
                   (Date.now() - new Date(row.last_reconcile_at).getTime()) > 30 * 60 * 1000;

    if (tooManyAttempts || tooOld) {
      await db.query(
        `UPDATE agent_idempotency
         SET state='manual_required', manual_required_at=now()
         WHERE key=$1 AND state IN ('pending','unknown')`,
        [row.key]
      );
      log.alert('idempotency_manual_required', {
        key: row.key,
        operation: row.operation_type,
        ref: row.resource_ref
      });
      pageOncall('idempotency_manual_required', { key: row.key });
      continue;
    }

    // Try to determine actual state
    const actualState = await checkResourceState(row.operation_type, row.resource_ref);
    await db.query(
      `UPDATE agent_idempotency
       SET reconcile_attempts = reconcile_attempts + 1, last_reconcile_at = now()
       WHERE key = $1`,
      [row.key]
    );

    if (actualState.kind === 'committed') {
      await transitionToCompleted(row.key, actualState.response);
    } else if (actualState.kind === 'not_found') {
      await transitionToFailed(row.key, { error: 'commit_lost' });
    }
    // else 'indeterminate': try again next pass
  }
}

async function checkResourceState(opType: string, ref: string): Promise<...> {
  // Examples:
  //   opType='revoke', ref='key:agk_aB1cD2eF'
  //     → SELECT rotation_state FROM agent_api_keys WHERE key_id='agk_aB1cD2eF'
  //     → if 'revoked': committed; if 'active': not_found (commit lost)
  //
  //   opType='rotate_emergency', ref='rotation:agk_old'
  //     → SELECT replaced_by_key_id FROM agent_api_keys WHERE key_id='agk_old'
  //     → if non-null: committed; else: not_found
  //
  //   opType='suspend_account', ref='account:<uuid>'
  //     → SELECT status FROM agent_accounts WHERE id=<uuid>
  //     → if 'suspended': committed; else: not_found
}
```

### 5.1.3 Failure semantics

- `failed`: terminal **business** failure (validation error, business rule violation). Retries return same response.
- `unknown`: infrastructure outcome unclear. Observer will reconcile.
- `manual_required`: observer gave up. Operator must inspect and manually resolve via admin CLI (RB-9).

## 5.2 Rate limiting (GCRA)

### 5.2.1 Algorithm

Generic Cell Rate Algorithm (GCRA) is a token bucket variant that's atomic per Redis key, more memory-efficient than sliding-log.

```lua
-- gcra.lua (atomic Redis script)
-- KEYS[1] = bucket key
-- ARGV[1] = period_seconds
-- ARGV[2] = burst_capacity (max units in window)
-- ARGV[3] = cost_units (default 1)
-- Returns: { allowed: 0|1, remaining_units: int, time_ms: int }
--   On accept: time_ms = reset_after_ms (when budget fully replenishes)
--   On reject: time_ms = retry_after_ms (when this exact cost would be allowed)

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

local rate = burst / period
local interval = cost / rate

local time = redis.call('TIME')
local now = tonumber(time[1]) + tonumber(time[2]) / 1e6

local last = redis.call('GET', key)
local tat = (last and tonumber(last)) or now

local allow_at = math.max(tat, now)
local new_tat = allow_at + interval

if (new_tat - now) > (burst / rate) then
  -- Reject: time until budget allows this cost
  local retry_after = math.max(0, new_tat - now - (burst / rate))
  return { 0, 0, math.ceil(retry_after * 1000) }
end

-- Accept
local ttl = math.ceil((new_tat - now) + period)
redis.call('SET', key, tostring(new_tat), 'EX', ttl)

local remaining_capacity = (burst / rate) - (new_tat - now)
local remaining_units = math.max(0, math.floor(remaining_capacity * rate))
return { 1, remaining_units, math.ceil((new_tat - now) * 1000) }
```

### 5.2.2 Multi-dimensional limits (v0.1)

```yaml
rate_limit:
  per_key:               { burst: 100,    period: 60s }     # 100 req/min/key
  per_account:           { burst: 5000,   period: 86400s }  # 5K req/day/account
  per_route_overrides:
    'POST /api/agent/v1/expensive': { cost_units: 10 }
  per_ip_registration:   { burst: 5,      period: 3600s }   # 5 reg/hour/IP
  global_emergency:      { burst: 1000000, period: 3600s }  # 1M req/hour total
  algorithm: gcra
  storage: redis
```

Order of checks (per-validation):
1. per_key
2. per_account
3. per_route + cost_units
4. global_emergency

If any rejects, request fails with 429 + retry_after_ms.

**Atomic limitation**: each check is atomic per-key, but checks across keys are NOT atomic (Redis cluster hash slots). For v0.1, single Redis primary makes this moot. For Redis cluster, document that limits are evaluated independently (acceptable for rate limiting; not a correctness issue).

## 5.3 Caching & invalidation

### 5.3.1 Cache layout

```
Redis keys (per validation):
  agent-auth:key:<key_id>                  → KeyCache (JSON, TTL 30s)
  agent-auth:revocation-epoch              → BIGINT global epoch (no TTL)
  agent-auth:account-keys:<account_id>     → SET of key_ids (no TTL, reconciled)

Local in-memory cache (per app process):
  - 1000-entry LRU
  - TTL 30s
  - Invalidated by Redis pubsub
```

### 5.3.2 Epoch update (Lua MAX)

```lua
-- redis-epoch-update.lua
-- KEYS[1] = epoch key
-- ARGV[1] = proposed epoch
-- Returns: actual epoch after update (max of proposed and existing)

local key = KEYS[1]
local proposed = tonumber(ARGV[1])
local current = tonumber(redis.call('GET', key) or '0')

if proposed > current then
  redis.call('SET', key, tostring(proposed))
  return proposed
end
return current
```

Invariant: epoch is monotonic. Concurrent revokes that increment Postgres epoch in different orders cannot decrement Redis epoch.

### 5.3.3 Validation flow with epoch check

```typescript
async function validateKey(keyId: string, secret: string): Promise<AgentContext> {
  // 1. Fetch authoritative epoch (uncached in strict mode)
  const currentEpoch = await getAuthoritativeEpoch();
  // strict_uncached: Redis GET (1 RTT)
  // bounded_stale_1s: local cache + Redis GET every 1s

  // 2. Local cache lookup
  const cached = localCache.get(keyId);
  if (cached && cached.cachedEpoch === currentEpoch) {
    if (cached.expiresAt < Date.now()) {
      localCache.delete(keyId);
    } else {
      return validateAgainstCache(cached, secret);
    }
  }

  // 3. Redis cache lookup
  const redisEntry = await redis.get(`agent-auth:key:${keyId}`);
  if (redisEntry) {
    const entry = JSON.parse(redisEntry);
    if (entry.cachedEpoch === currentEpoch) {
      localCache.set(keyId, entry);
      return validateAgainstCache(entry, secret);
    }
  }

  // 4. Postgres lookup (authoritative)
  const row = await db.queryOne(
    `SELECT k.*, a.status AS account_status, a.tier AS account_tier,
            i.status AS issuing_identity_status
     FROM agent_api_keys k
     JOIN agent_accounts a ON a.id = k.account_id
     JOIN agent_identities i ON i.id = k.issued_via_identity_id
     WHERE k.key_id = $1`,
    [keyId]
  );
  if (!row) return reject(401, 'key_not_found');

  // 5. Build cache entry
  const entry: KeyCache = {
    accountId: row.account_id,
    accountStatus: row.account_status,
    keyHash: row.key_hash,
    keyPepperVersion: row.key_pepper_version,
    scopes: row.scopes,
    tier: row.tier,
    rotationState: row.rotation_state,
    revokedAt: row.revoked_at,
    graceExpiresAt: row.rotation_grace_expires_at,
    expiresAt: row.expires_at,
    issuingIdentityId: row.issued_via_identity_id,
    issuingIdentityStatus: row.issuing_identity_status,
    cachedEpoch: currentEpoch,
    cachedAt: Date.now(),
    redisExpiry: Date.now() + 30000  // 30s
  };

  // 6. Populate caches
  await redis.set(`agent-auth:key:${keyId}`, JSON.stringify(entry), 'EX', 30);
  localCache.set(keyId, entry);

  // 7. Validate
  return validateAgainstCache(entry, secret);
}

function validateAgainstCache(cache: KeyCache, secret: string): AgentContext {
  // Account status
  if (cache.accountStatus !== 'active') {
    return reject(401, 'account_' + cache.accountStatus);
  }
  // Issuing identity status
  if (cache.issuingIdentityStatus !== 'active') {
    return reject(401, 'identity_revoked');
  }
  // Rotation state
  if (cache.rotationState === 'revoked') {
    return reject(401, 'key_revoked');
  }
  if (cache.rotationState === 'rotated') {
    return reject(401, 'key_rotated');
  }
  if (cache.rotationState === 'rotating') {
    if (cache.graceExpiresAt && Date.now() >= new Date(cache.graceExpiresAt).getTime()) {
      enqueueAsync(() => transitionRotatedState(cache));
      return reject(401, 'rotation_grace_expired');
    }
  }
  // Expiration
  if (cache.expiresAt && Date.now() >= new Date(cache.expiresAt).getTime()) {
    return reject(401, 'key_expired');
  }
  // HMAC verification (constant time)
  const pepper = await kms.getPepperByVersion(cache.keyPepperVersion);
  const expected = hmacSha256(pepper, secret);
  if (!constantTimeEqual(expected, cache.keyHash)) {
    return reject(401, 'invalid_secret');
  }
  // Build req.agent
  return buildAgentContext(cache);
}
```

### 5.3.4 Invalidation on revoke

```typescript
async function invalidateKey(keyId: string) {
  // Delete from Redis cache
  await redis.del(`agent-auth:key:${keyId}`);
  // Publish to all subscribers (other app processes)
  await redis.publish(`agent-auth:invalidate:key:${keyId}`, '1');
}

// Each app process subscribes:
redis.subscribe('agent-auth:invalidate:key:*', (channel, message) => {
  const keyId = channel.split(':').slice(-1)[0];
  localCache.delete(keyId);
});
```

### 5.3.5 Account-wide invalidation

```typescript
async function invalidateAccountKeys(accountId: string) {
  // CORRECTNESS: always Postgres (Redis SET is acceleration only)
  const dbResult = await db.query(
    `SELECT key_id FROM agent_api_keys
     WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
    [accountId]
  );
  const keyIds = dbResult.rows.map(r => r.key_id);

  // Acceleration: also invalidate via Redis
  if (keyIds.length > 0) {
    const pipeline = redis.pipeline();
    for (const kid of keyIds) {
      pipeline.del(`agent-auth:key:${kid}`);
      pipeline.publish(`agent-auth:invalidate:key:${kid}`, '1');
      pipeline.srem(`agent-auth:account-keys:${accountId}`, kid);
    }
    pipeline.exec().catch(err =>
      log.warn('cache_invalidation_partial_failure', { err: err.message })
    );
  }

  // Note: do NOT DEL the account-keys SET here. SET lifecycle is account creation
  // → account closure. Stale entries are harmless; missing entries are dangerous.
}
```

### 5.3.6 Reconciliation job (Redis SET drift)

Hourly:
```typescript
async function reconcileAccountKeySets() {
  const accounts = await db.query(
    `SELECT id FROM agent_accounts
     WHERE status = 'active' AND updated_at > now() - interval '7 days'`
  );

  for (const acc of accounts.rows) {
    const dbKeys = await db.query(
      `SELECT key_id FROM agent_api_keys
       WHERE account_id = $1 AND rotation_state IN ('active', 'rotating')`,
      [acc.id]
    );
    const dbKeySet = new Set(dbKeys.rows.map(r => r.key_id));

    const redisKeys = await redis.smembers(`agent-auth:account-keys:${acc.id}`);
    const redisKeySet = new Set(redisKeys);

    const missingInRedis = [...dbKeySet].filter(k => !redisKeySet.has(k));
    const staleInRedis = [...redisKeySet].filter(k => !dbKeySet.has(k));

    if (missingInRedis.length > 0) {
      await redis.sadd(`agent-auth:account-keys:${acc.id}`, ...missingInRedis);
      metrics.increment('agent_auth.reconciliation.added', missingInRedis.length);
    }
    if (staleInRedis.length > 0) {
      await redis.srem(`agent-auth:account-keys:${acc.id}`, ...staleInRedis);
      metrics.increment('agent_auth.reconciliation.removed', staleInRedis.length);
    }

    const card = await redis.scard(`agent-auth:account-keys:${acc.id}`);
    if (card > 1000) {
      log.warn('account_key_set_too_large', { account_id: acc.id, scard: card });
    }
  }
}
```

## 5.4 Circuit breakers (upstream IdP)

```typescript
const githubBreaker = new CircuitBreaker({
  failureThreshold: 5,           // 5 failures in 60s
  failureWindow: 60_000,
  halfOpenAfter: 30_000,         // try again after 30s
  halfOpenProbeCount: 1,         // single probe
  onOpen: () => {
    log.alert('github_circuit_breaker_open');
    metrics.set('agent_auth.idp.github.circuit_open', 1);
  },
  onClose: () => {
    metrics.set('agent_auth.idp.github.circuit_open', 0);
  }
});

async function exchangeCodeWithGithub(code: string, ...): Promise<...> {
  return githubBreaker.execute(async () => {
    const resp = await fetch('https://github.com/login/oauth/access_token', { ... });
    if (!resp.ok) throw new UpstreamError(resp.status);
    return resp.json();
  });
}
```

When circuit opens: registration via that provider fails fast with 503. Lib emits Prometheus metric `agent_auth_idp_github_circuit_open` for alerting.


---

# Part VI — Security & Threat Model

## 6.1 Cryptographic primitives

| Use | Primitive | Library |
|---|---|---|
| API key hashing | HMAC-SHA256 with KMS-held pepper | AWS KMS / GCP KMS |
| Sealed-box delivery | X25519 + XSalsa20-Poly1305 | libsodium `crypto_box_seal` |
| Webhook signature | HMAC-SHA256 | `node:crypto` constant-time compare |
| Audit hash chain | SHA-256 over canonical JSON | `node:crypto` |
| OAuth PKCE challenge | SHA-256 (S256) | `node:crypto` |
| Key generation | OS CSPRNG (256-bit) | `crypto.randomBytes` / `sodium.randombytes_buf` |
| IP pseudonymization | HMAC-SHA256 with internal_secret | `node:crypto` |
| TLS | TLS 1.3 minimum | OS / language runtime |
| Device flow code encryption | AES-256-GCM with KMS key | KMS envelope encryption |

### 6.1.1 Why HMAC + pepper instead of Argon2id for API keys

API keys are 256-bit random secrets. Argon2id is designed for low-entropy human-memorable passwords (slow hash to defeat dictionary attacks). For high-entropy random bearer tokens:

- **HMAC-SHA256 + KMS-held pepper** provides equivalent security against database compromise
  - Attacker needs both DB dump AND KMS access to recover secrets
  - Verification is ~1-10μs vs Argon2id's ~30ms
  - Industry-aligned: GitHub, Cloudflare, Stripe documentation suggests similar patterns for high-entropy tokens

- Argon2id is reserved for human-memorable secrets (admin passwords, recovery questions if any)

### 6.1.2 KMS pepper rotation

```yaml
kms:
  pepper_key_alias: alias/agent-auth-pepper
  rotation_cadence_days: 90
  dual_pepper_window_days: 7    # both old and new accepted
```

During rotation:
- New keys hashed with new pepper, `key_pepper_version = N+1`
- Existing keys with `key_pepper_version = N` continue to work
- Background job re-hashes existing keys to new pepper (lazy or batched)
- After all keys upgraded, old pepper key can be archived (not destroyed; needed for audit replay)

## 6.2 Threat model (44 scenarios)

### 6.2.1 Identity & session

| # | Threat | Mitigation |
|---|---|---|
| RT-1 | Phishing user to authorize attacker's GitHub App | Out of scope (attacker controls user). SaaS UX clearly identifies app. |
| RT-2 | Steal poll_token via XSS in callback page | Callback page contains zero secrets, CSP enforces no-script. |
| RT-19 | Forged /recover-account-confirm callback | Canonical HMAC over method+path+timestamp+nonce+request_id+body_hash; 5-min skew check; nonce SET NX EX. |
| RT-20 | Client public-key substitution during sealed-box delivery | client_pubkey bound to poll_token at /begin-registration; immutable. |
| RT-21 | Session fixation around recovery/poll | poll_token entropy 256-bit; immutable kind once issued; cryptographic prefix (`pak_`/`pkr_`/`pad_`/`pav_`) bound to kind. |
| RT-29 | OAuth state/challenge phishing | `state=<256-bit nonce>` bound to session; PKCE verifier in DB only; exact redirect_uri match. |
| RT-31 | Tenant confused-deputy in recovery | recovery session bound to target_account_id at /begin-registration; identity match check at /callback. |

### 6.2.2 Storage & infrastructure

| # | Threat | Mitigation |
|---|---|---|
| RT-3 | Compromise Redis | Cache only; no plaintext secrets. Argon-free HMAC hashes in Postgres only. Worst case 30s stale auth. |
| RT-4 | Compromise Postgres replica | HMAC hashes (not plaintext) for keys. IP pseudonymized with HMAC. PII minimized in audit log. |
| RT-12 | Postgres primary compromise | All admin ops audited externally (S3 WORM); DB credentials short-lived (Vault); audit log hash chain detects tampering. |
| RT-13 | Backup compromise | Backups encrypted at rest (KMS); restore requires multi-party approval; tombstone reapply on restore. |
| RT-23 | Backup restore resurrecting revoked state | Tombstone application during restore; quarterly DR drill includes tombstone reapply test. |
| RT-26 | Redis stale epoch / split-brain | Validation falls through to Postgres on epoch mismatch or Redis unavailability. |
| RT-37 | KMS key deletion / policy takeover | KMS admin in separate AWS account; key deletion requires 7-day waiting + two-person approval; CloudTrail alarms. |

### 6.2.3 Supply chain & release

| # | Threat | Mitigation |
|---|---|---|
| RT-5 | npm pkg attack (transitive) | Sigstore signing + npm provenance + SBOM attestation + SLSA L3 + Scorecard ≥ 8.5 + pinned deps. |
| RT-14 | CI/CD release pipeline compromise | OIDC trusted publishing; protected branches; two-person review on tags; phishing-resistant maintainer MFA. |
| RT-35 | Supply-chain compromise (transitive npm dep) | Lockfile + `npm ci`; manual review for new transitive deps; OpenSSF Scorecard ≥ 8.5 gate. |
| RT-36 | CI/CD credential abuse (compromised GitHub token) | Trusted publishing OIDC; protected branches; ephemeral tokens; OIDC audience binding. |
| RT-38 | SSO/IdP compromise (admin SSO) | Independent break-glass admin path; audit SSO logins; periodic SSO config attestation. |

### 6.2.4 Operational

| # | Threat | Mitigation |
|---|---|---|
| RT-10 | Privileged admin abuse | RBAC + WebAuthn/FIDO2 hardware key + two-person rule + audit log + JIT RBAC. |
| RT-11 | Privileged operator misuse | Read-only by default; audit all DB-direct queries; admin role separate from app role. |
| RT-15 | DoS / cost exhaustion attack | Per-IP/ASN rate limit; global emergency brake; alarm on cost spike; circuit breakers. |
| RT-39 | Audit event omission by compromised app | Outbox pattern + reconciliation observer + WORM external audit; missing events trigger alarm. |
| RT-41 | Recovery approver compromise | Two-person rule for high-value recovery; approval webhook signature with rotating secret; post-approval audit alert. |
| RT-43 | Fail-closed DoS amplification | Circuit breaker on fail-closed paths: if X% fail-closed in 1min, switch to degraded mode + operator alert. |

### 6.2.5 Application-layer attacks

| # | Threat | Mitigation |
|---|---|---|
| RT-6 | Replay GitHub webhook | HMAC verify FIRST; dedup via X-GitHub-Delivery; payload_hash mismatch alert. |
| RT-7 | Steal API key from agent process memory | Outside lib boundary. Mitigations: short-lived keys, scope minimization, leaked-prefix scanner (GitHub search for `agk_` prefix). |
| RT-8 | Time-based farming (Sybil at warm tier) | Documented compromise. Warm tier MUST NOT unlock expensive ops. SaaS owner gates hot tier. |
| RT-9 | Cross-tenant access (BOLA) | Every query scoped by account_id; integration tests prove isolation; req.agent.account_id never confused with req.user. |
| RT-25 | Redis partition during validation | Lib falls through to Postgres directly (degraded but correct). |
| RT-27 | Idempotency replay with mismatched payload | request_hash compared; mismatch returns 409 with audit alert. |
| RT-30 | GitHub webhook spoof / order gaps | HMAC-SHA256 verify first; dedup via X-GitHub-Delivery; payload_hash mismatch alert; out-of-order events idempotent. |
| RT-44 | Observability/APM secret leakage | OTEL exporter scrubs span attrs; metric labels never include subjects/keys; explicit allow-list. |

### 6.2.6 Disaster & failover

| # | Threat | Mitigation |
|---|---|---|
| RT-18 | Failover race during rotation | Synchronous replication (Tier B) for revocations; cross-region revocation log; readiness gate post-promotion. |
| RT-22 | KMS/HSM signing key compromise | Keys isolated in HSM; rotation procedure documented; lib fails closed if KMS unreachable. |
| RT-24 | GitHub account takeover / SAML deprovisioning | Lib responds to webhook revocation; SaaS owner can manually revoke; reauth required on cadence. |
| RT-28 | WORM write suppression / KMS destruction | Trust-domain separation across 3 AWS accounts; KMS rotation requires two-person; outbox pattern blocks Tier B on audit unavailable. |
| RT-32 | Clock skew across regions | Operations use Postgres now() (single clock per region); cross-region uses LSN; webhook timestamps allow ±5min skew. |
| RT-33 | Metrics/log secret leakage | Allow-listed log fields; substring entropy scan; metric labels never include subject/key_id raw. |
| RT-34 | Multi-region failover divergence | Tier B sync replication blocks until standby ack; failover decision tree handles lag-aware promotion. |
| RT-40 | Backup restore revocation rollback | Post-restore tombstone reapply procedure + integration test; revocation log replayed from cross-region log. |
| RT-42 | Webhook secret rotation race | Dual-secret support during rotation: lib accepts both old + new for 24h; Redis SET tracks active secrets. |

### 6.2.7 Out of scope (explicitly)

| # | Threat | Why not lib's responsibility |
|---|---|---|
| RT-16 | Agent's host machine compromised | Outside lib boundary; agent SDK responsibility (key in keychain, etc.) |
| RT-17 | User's GitHub account compromised | Upstream provider responsibility; we react to revocation webhook |

CI integration tests must exercise each in-scope mitigation. Failure of any test blocks release.

## 6.3 Confused-deputy prevention

```typescript
// Type augmentation
declare module 'express' {
  interface Request {
    agent?: AgentContext;
    // NOTE: req.user is INTENTIONALLY NOT extended. Disjoint contexts.
  }
}

interface AgentContext {
  readonly account_id: string;
  readonly key_id: string;
  readonly identity: Readonly<{
    provider: string;
    subject: string;
    display_handle?: string;
    assurance_level: 'low' | 'medium' | 'high';
  }>;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: 'cold' | 'warm' | 'hot';
  has_scope(scope: string): boolean;
  require_scope(scope: string): void;  // throws 403 if missing
}

function buildAgentContext(cache: KeyCache): AgentContext {
  const scopes = Object.freeze([...cache.scopes]);
  const identity = Object.freeze({
    provider: cache.identity_provider,
    subject: cache.identity_subject,
    display_handle: cache.identity_display_handle,
    assurance_level: cache.identity_assurance_level
  });
  const ctx: AgentContext = Object.freeze({
    account_id: cache.account_id,
    key_id: cache.key_id,
    identity,
    scopes,
    tier: cache.tier,
    has_scope: (s: string) => scopes.includes(s),
    require_scope: (s: string) => {
      if (!scopes.includes(s)) {
        throw new AgentAuthError(403, 'insufficient_scopes', { required: s });
      }
    }
  });
  return ctx;
}
```

**Lint rule** (shipped in eslint config): warn if `req.user` is read in a route protected by `agents.middleware`.

## 6.4 Audit log architecture

### 6.4.1 In-database (hash chain)

See Section 3.8. Every row's `row_hash` includes previous row's hash. Tamper detection job runs hourly:

```typescript
async function verifyAuditHashChain() {
  const today = await db.query(
    `SELECT id, prev_hash, row_hash, ts FROM agent_audit_log
     WHERE ts >= date_trunc('day', now())
     ORDER BY id ASC`
  );

  for (let i = 1; i < today.rows.length; i++) {
    if (!Buffer.from(today.rows[i].prev_hash, 'hex').equals(
        Buffer.from(today.rows[i-1].row_hash, 'hex'))) {
      log.alert('audit_hash_chain_break', {
        at_id: today.rows[i].id,
        ts: today.rows[i].ts
      });
      pageOncall('audit_hash_chain_break');
      return;
    }
  }
}
```

### 6.4.2 External WORM (S3 Object Lock)

```yaml
audit:
  external_worm:
    bucket: my-audit-worm-bucket
    aws_account: 222222222222         # SEPARATE from app account
    region: us-east-1
    retention_years: 7
    object_lock_mode: COMPLIANCE      # immutable, cannot delete or overwrite
    write_cadence: realtime
    encryption: kms_managed
    kms_key_alias: alias/audit-encryption
    kms_aws_account: 333333333333     # SEPARATE from audit reader
```

S3 Object Lock COMPLIANCE mode prevents deletion/overwrite even by AWS root account during retention period. Trust-domain separation: app account writes, separate audit-reader account reads, separate KMS-admin account manages encryption keys.

```typescript
async function writeAudit(event: AuditEvent) {
  const key = `audit/${dateShard(event.ts)}/${event.id}.json`;
  try {
    await s3.putObject({
      Bucket: config.audit.external_worm.bucket,
      Key: key,
      Body: JSON.stringify(event),
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: config.audit.external_worm.kms_key,
      ObjectLockMode: 'COMPLIANCE',
      ObjectLockRetainUntilDate: addYears(new Date(), 7)
    });
  } catch (err) {
    // Outbox: queue for retry
    await db.query(
      `INSERT INTO agent_audit_outbox (event_id, payload, error, created_at)
       VALUES ($1, $2, $3, now())`,
      [event.id, event, err.message]
    );
    metrics.increment('agent_auth.audit.worm_write_failed');
    // For Tier B operations: BLOCK until outbox flushed
    if (event.tier === 'B') {
      throw new ServiceUnavailableError(503, 'audit_unavailable');
    }
  }
}
```

Outbox processor flushes in background. If outbox depth > 10K rows: alert and halt new Tier B writes.

## 6.5 Trust domain separation

Three AWS accounts:

```yaml
account_111111111111:                # Application
  role: agent-auth-app-role
  permissions:
    - rds:connect (Postgres)
    - elasticache:connect (Redis)
    - kms:encrypt/decrypt (pepper, sealed box)
    - s3:putObject (audit WORM, no read/delete)

account_222222222222:                # Audit Reader (separate trust domain)
  role: audit-reader-role
  permissions:
    - s3:getObject (audit WORM bucket)
    - cloudtrail:lookupEvents
    - mfa: required
    - quarterly attestation: required

account_333333333333:                # KMS Admin (separate trust domain)
  role: kms-admin
  permissions:
    - kms:scheduleKeyDeletion (with 30-day delay)
    - kms:rotateKeyOnDemand
    - kms: cannot decrypt audit (separate per-purpose keys)
  required_approvals: 2
```

Compromise of any single account does not enable audit log tampering. Compromise of all three would still face S3 Object Lock COMPLIANCE retention.

## 6.6 PII / data handling rules

```yaml
pii_handling:
  classification:
    high:
      - api_key_secret (Argon-free HMAC hashed only, never logged)
      - upstream_oauth_tokens (verified once, discarded; never persisted)
    medium:
      - upstream_subject_id (durable, used as identity key)
      - account_id (UUID)
      - audit_log_meta (allow-listed, scrubbed)
    low:
      - tier, scopes, timestamps
      - display_handle (mutable, advisory)
  storage:
    plaintext_in_db:
      - subject_id, display_handle, scopes, tier
    hashed_only:
      - api_key (HMAC-SHA256 with KMS pepper)
    pseudonymized:
      - ip_address (HMAC-SHA256 with internal_secret)
      - audit subject IDs (HMAC with rotating pepper for crypto-erasure)
    never_stored:
      - oauth_access_tokens (default mode)
      - request bodies in audit log
      - response bodies in audit log
      - credit card data
      - email (unless SaaS opts in via config)
  log_scrubbing:
    redact_value_patterns:
      - /agk_[A-Za-z0-9_-]{8}_[A-Za-z0-9_-]{43}/    # our keys
      - /ghp_[A-Za-z0-9]{36,}/                       # GitHub PAT
      - /github_pat_[A-Za-z0-9_]+/                   # GitHub fine-grained
      - /sk-ant-[A-Za-z0-9-]+/                       # Anthropic
      - /sk-[A-Za-z0-9]{40,}/                        # OpenAI
    redact_key_name_patterns:
      - /authorization/i, /token/i, /secret/i
      - /password/i, /cookie/i, /credential/i
      - /private/i, /key$/i
    high_entropy_threshold: 4.5_bits_per_char
    max_string_length: 1024
    max_jsonb_depth: 4
    max_serialized_size_kb: 4
```


---

# Part VII — Observability

## 7.1 Metrics (Prometheus exposition format)

### 7.1.1 Counters

```
agent_auth_registrations_total{provider, kind, outcome}
agent_auth_keys_issued_total{tier, identity_provider}
agent_auth_keys_rotated_total{type=planned|emergency}
agent_auth_keys_revoked_total{reason}
agent_auth_validations_total{outcome=accepted|rejected, reject_reason}
agent_auth_rate_limit_hits_total{dimension=per_key|per_account|per_route|per_ip}
agent_auth_webhook_events_total{provider, event_type, status}
agent_auth_webhook_replay_redelivered_total{provider}
agent_auth_idempotency_state_transitions_total{from, to}
agent_auth_audit_writes_total{destination=db|worm, outcome}
agent_auth_kms_operations_total{operation=encrypt|decrypt|generate_mac, outcome}
agent_auth_tier_b_unknown_outcome_total
agent_auth_tier_b_standby_unreachable_total
agent_auth_redis_reconciliation_total{kind=added|removed}
```

### 7.1.2 Gauges

```
agent_auth_keys_active
agent_auth_accounts_by_tier{tier}
agent_auth_pending_registrations
agent_auth_redis_quorum_acks
agent_auth_circuit_breaker_open{provider}
agent_auth_replication_lag_bytes{region}
agent_auth_audit_outbox_depth
```

### 7.1.3 Histograms

```
agent_auth_validation_latency_seconds (buckets: 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1)
agent_auth_registration_total_duration_seconds
agent_auth_provider_call_latency_seconds{provider, operation}
agent_auth_revoke_latency_seconds (Tier B end-to-end)
agent_auth_cache_lookup_latency_seconds{layer=local|redis|postgres}
```

## 7.2 Structured logging

Every log line includes:

```json
{
  "ts": "2026-04-30T12:00:00.123Z",
  "level": "info|warn|error|alert",
  "request_id": "<UUID>",
  "agent_auth_version": "1.0.0",
  "endpoint": "POST /api/agent-auth/register",
  "account_id": "<UUID>" | null,
  "key_id": "agk_aB1cD2eF" | null,
  "result": "ok|fail|...",
  "duration_ms": 12.3,
  "scrubbed_meta": { ... }
}
```

Scrubbing rules from Section 6.6 apply to ALL log output.

## 7.3 OpenTelemetry traces

Top-level span per public endpoint. Child spans:

- `idp.<provider>.<op>` (e.g. `idp.github.exchange_code`)
- `cache.lookup` with `layer` attribute
- `cache.invalidate` with `key_count` attribute
- `rate_limit.check` per dimension
- `db.query` with `op` attribute (anonymized SQL)
- `redis.eval` with script name
- `kms.<operation>`

Span attributes never include secrets; all values pass through scrubber.

## 7.4 Service Level Objectives

```yaml
slo:
  validation_latency_p50_ms:
    target: 5
    measurement_window: 30d
    alert_burn_rate_threshold: 14  # 14x error budget burn rate triggers alert
  validation_latency_p99_ms:
    target: 50
    measurement_window: 30d
    alert_burn_rate_threshold: 6
  validation_availability:
    target: 99.95
    measurement_window: 30d
  registration_success_rate:
    target: 99.5
    measurement_window: 7d
  webhook_processing_p50_ms:
    target: 100
    measurement_window: 7d
  cache_hit_rate:
    target: 95.0
    measurement_window: 30d
  tier_b_revocation_visibility_p99_ms:
    target: 100
    measurement_window: 7d
    mode: strict_uncached
```

## 7.5 Required alerts

| Alert | Condition | Severity | Runbook |
|---|---|---|---|
| validation_availability_breach | success rate < 99.95% over 30m | P1 | RB-2 |
| cache_hit_rate_drop | < 80% for 5min | P2 | RB-4 |
| webhook_replay_cap_hit | catch-up cap reached | P2 | RB-3 |
| redis_reconciliation_drift | drift > 5% of accounts | P3 | RB-7 |
| identity_reactivation_spike | rate > 10x baseline | P2 | RB-5 |
| audit_hash_chain_break | tamper detection | P0 | RB-6 |
| audit_worm_write_failed | outbox depth > 1000 | P1 | RB-6 |
| tier_b_unknown_outcome | > 5 in 1h | P1 | RB-3 |
| tier_b_standby_unreachable | > 1 in 5min | P0 | RB-3 |
| github_circuit_breaker_open | open > 5min | P2 | RB-4 |
| replication_lag_exceeded | secondary lag > threshold | P2 | RB-8 |
| timeline_mismatch | post-failover detection | P0 | RB-8 |

---

# Part VIII — Operations & Runbooks

## 8.1 Admin CLI

```bash
agent-auth admin <command> [options]

Authentication:
  Requires WebAuthn / FIDO2 hardware key for ALL destructive operations.
  TOTP allowed only for read-only queries.
  Two-person rule for: close-account, flush-cache, migrate-rollback,
                       export-account, reset-barrier, force-revoke-all.
```

### 8.1.1 Common commands

```bash
# Read-only
agent-auth admin list-accounts [--tier=cold|warm|hot]
agent-auth admin show-account <account_id>
agent-auth admin list-keys [--account-id=<uuid>]
agent-auth admin show-key <key_id>
agent-auth admin audit-tail [--lines=N]

# Single-user destructive
agent-auth admin revoke-key --key-id=<key_id> --reason="..."
agent-auth admin suspend-account --account-id=<uuid> --reason="..."
agent-auth admin unblock-identity --identity-id=<uuid> --reason="..."
agent-auth admin promote-tier --account-id=<uuid> --tier=hot --reason="..."

# Two-person rule required
agent-auth admin close-account --account-id=<uuid> --reason="..."
agent-auth admin flush-cache --confirm
agent-auth admin force-revoke-all --account-id=<uuid> --reason="..."
agent-auth admin export-account --account-id=<uuid> --format=json --include-audit
agent-auth admin reset-barrier  # post-failover only

# Operational
agent-auth backfill --provider=github_app --lookback-hours=168
agent-auth migrate --target-version=v7
agent-auth migrate --rollback
agent-auth verify-audit-chain --since=<iso>
agent-auth admin reconcile-redis-sets
```

### 8.1.2 Configuration

```yaml
# agent-auth-admin.yaml
admin:
  oidc_issuer: "https://accounts.google.com/o/saml2?idpid=..."
  required_mfa: webauthn
  totp_fallback_for_readonly: true
  two_person_required_for:
    - close-account
    - flush-cache
    - migrate-rollback
    - export-account
    - force-revoke-all
    - reset-barrier
  audit_admin_ops: true
  approval_timeout_seconds: 600
  device_posture:
    require_managed_device: true
    require_mdm_attested: true
  jit_rbac:
    enabled: true
    role_grant_ttl: 3600   # 1 hour
    audit_grant_revoke: true
  break_glass:
    procedure: docs/break_glass.md
    requires_co_signer: true
    incident_post_mortem: required_within_24h
```

## 8.2 Runbooks

### 8.2.1 RB-1: Force-revoke a specific key

**When**: customer reports compromised API key, or leaked-prefix scanner finds public exposure.

```bash
# Step 1: identify
agent-auth admin show-key agk_aB1cD2eF

# Step 2: revoke (Tier B operation)
agent-auth admin revoke-key \
  --key-id=agk_aB1cD2eF \
  --reason="customer_reported_compromise"

# What happens internally:
# - Postgres update (sync replicated)
# - revocation_epoch bumped
# - revocation_barrier updated
# - Redis DEL + PUBLISH
# - Audit log entry (DB + WORM)
# - Operation idempotent via Idempotency-Key

# Step 3: verify
agent-auth admin show-key agk_aB1cD2eF
# rotation_state should be 'revoked' with revoked_at set

# Step 4: notify customer (out-of-band)
```

### 8.2.2 RB-2: Suspend account (cascade revoke all keys)

```bash
agent-auth admin suspend-account \
  --account-id=ec5b3df0-7a91-4f7a-b8c2-1d9e2f4a8b6c \
  --reason="abuse_investigation_pending"

# Cascade: Tier B for revocations
# - All keys revoked (atomic with account update)
# - All identities marked suspended
# - Redis flushed for account
# - Audit log entry
# - Customer/owner webhook fired (if configured)
```

### 8.2.3 RB-3: Tier B unknown outcome resolution

**When**: alert `tier_b_unknown_outcome` fires (idempotency observer cannot reconcile).

```bash
# Step 1: list manual_required idempotency rows
psql -c "SELECT key, operation_type, resource_ref, manual_required_at
         FROM agent_idempotency
         WHERE state = 'manual_required'
         ORDER BY manual_required_at DESC LIMIT 50;"

# Step 2: for each row, manually inspect
# Example: opType='revoke', ref='key:agk_aB1cD2eF'
psql -c "SELECT rotation_state, revoked_at FROM agent_api_keys
         WHERE key_id = 'agk_aB1cD2eF';"

# If rotation_state='revoked': operation succeeded, mark completed
# If rotation_state='active': operation lost, mark failed (consumer must retry with new Idempotency-Key)

# Step 3: admin override
agent-auth admin resolve-idempotency \
  --key=<idempotency_key> \
  --decision=completed|failed \
  --reason="manual_inspection_postgres_state_<state>"
```

### 8.2.4 RB-4: Cache flush (incident response)

**When**: cache poisoning suspected, or after major data correction.

```bash
# Step 1: confirm with co-signer
agent-auth admin flush-cache --confirm

# What happens:
# - All Redis keys matching 'agent-auth:*' deleted
# - Validations fall back to Postgres for next 30s
# - Increased load on DB; monitor CPU
# - Cache repopulates organically

# Step 2: monitor cache_hit_rate metric
# Should return to >95% within 5 min
```

### 8.2.5 RB-5: Identity unblock (admin override)

**When**: false positive on manual revocation; user contests block.

```bash
agent-auth admin unblock-identity \
  --identity-id=<uuid> \
  --reason="false_positive_after_review"

# What happens:
# - identity.status: revoked → active
# - revocation_source set to 'admin' (override)
# - Audit log: 'identity_admin_unblock' with admin user, co-signer, reason
# - Old keys: still revoked (must re-issue via /issue-key)
```

### 8.2.6 RB-6: Audit log tamper response

**When**: alert `audit_hash_chain_break` fires.

```bash
# Step 1: STOP all admin operations immediately
# Step 2: snapshot DB and Redis
pg_dump -Fc > /backups/incident-$(date +%s).dump
redis-cli SAVE && cp /var/lib/redis/dump.rdb /backups/incident-$(date +%s).rdb

# Step 3: cross-reference DB hash chain with WORM
agent-auth verify-audit-chain --since=<24h ago> --compare-worm

# Step 4: identify divergence point
# - If WORM matches DB up to point T: tampering after T
# - If WORM and DB diverge throughout: WORM may be authoritative

# Step 5: incident response
# - File security incident ticket
# - Engage CISO
# - Public disclosure decision per legal
# - Restore from PITR + reapply tombstones
```

### 8.2.7 RB-7: Redis reconciliation drift

```bash
# When alert fires
agent-auth admin reconcile-redis-sets

# What it does:
# - Walks all active accounts (active in last 7 days)
# - Compares DB key list to Redis SET
# - SADD missing, SREM stale
# - Reports drift count
```

### 8.2.8 RB-8: Post-failover barrier reset

**When**: Postgres primary failed over, app pods coming up on new primary.

```bash
# This runs automatically as K8s post-promotion hook.
# Manual procedure if automation fails:

# Step 1: verify new primary
psql -c "SELECT pg_is_in_recovery();"  # should return false

# Step 2: capture new timeline + LSN
NEW_LSN=$(psql -tAc "SELECT pg_current_wal_insert_lsn()")
NEW_TIMELINE=$(psql -tAc "SELECT timeline_id FROM pg_control_checkpoint()")

# Step 3: update barrier
psql <<SQL
UPDATE agent_revocation_barrier
SET last_lsn = '$NEW_LSN'::pg_lsn,
    timeline_id = $NEW_TIMELINE,
    updated_at = now()
WHERE id = 1;
SQL

# Step 4: flush Redis
redis-cli FLUSHDB

# Step 5: emit promotion event
psql -c "INSERT INTO agent_audit_log (ts, event_type, meta)
         VALUES (now(), 'promotion_completed',
                 jsonb_build_object('new_timeline', $NEW_TIMELINE,
                                   'new_barrier_lsn', '$NEW_LSN'));"

# Step 6: signal app readiness
touch /var/lib/agent-auth/ready

# Step 7: monitor /api/agent-auth/healthz endpoint
curl https://saas.com/api/agent-auth/healthz
# Expected: { "status": "healthy", "timeline": NEW_TIMELINE }
```

### 8.2.9 RB-9: Webhook missed-delivery backfill

```bash
# When extended outage caused missed webhooks > 72h ago
agent-auth backfill --provider=github_app --lookback-hours=720

# Note: GitHub limits redelivery to past 3 days.
# For older missed events, forced fresh OAuth on user activity covers it.
```

## 8.3 Disaster recovery

### 8.3.1 Backup strategy

```yaml
backups:
  postgres:
    method: pgBackRest
    pitr: enabled
    full_backup_cadence: weekly
    incremental_cadence: hourly
    retention: 30d
    storage: s3 (encrypted, separate bucket from audit WORM)
    test_restore_cadence: quarterly
  redis:
    method: rdb_snapshot
    cadence: hourly
    retention: 7d
    note: "ephemeral state OK to lose; rate limit + cache rebuild quickly"
  config:
    storage: k8s_sealed_secrets / vault
    encrypted_at_rest: true
    backup_to: s3 (yet another bucket)
```

### 8.3.2 RTO/RPO targets

| Component | RTO | RPO |
|---|---|---|
| Postgres primary | 1 hour | 5 minutes (Tier A); 0 (Tier B with sync standby) |
| Redis primary | 1 minute | 30 seconds (cache rebuild) |
| KMS | depends on cloud provider | 0 (managed) |
| Audit WORM | 0 (multi-AZ S3) | 0 |
| Application | 5 minutes (K8s pod restart) | N/A |

### 8.3.3 Quarterly DR drill

```yaml
drill_procedure:
  - restore_postgres_from_yesterday_backup_to_staging
  - replay_recent_wal_to_specific_lsn
  - verify_data_integrity (checksums, row counts, audit chain)
  - reapply_tombstones_for_erased_accounts
  - run_integration_tests against restored DB
  - measure_actual_rto
  - document_findings
  - update_runbooks_if_needed
```

## 8.4 Capacity planning

```yaml
capacity:
  per_app_pod:
    target_cpu: 60%
    target_memory: 70%
    max_concurrent_validations: 1000
    max_concurrent_registrations: 50
  scaling:
    horizontal: K8s HPA based on CPU/memory + custom metric (validation_latency_p99)
    min_replicas: 3
    max_replicas: 50
  postgres:
    primary_size: 8 vCPU / 32GB / 500GB SSD (initial)
    standby: same as primary
    monitoring: pg_stat_statements, slow query log
  redis:
    primary_size: 4 vCPU / 16GB
    replica: same
    eviction_policy: noeviction (lib expects keys to persist; no LRU)
```


---

# Part IX — Compliance

## 9.1 SOC 2 control mapping

```
CC6.1 (Logical access)
  Controls:
    - OAuth + PKCE for upstream identity verification
    - HMAC-SHA256 + KMS pepper for API keys
    - Sealed-box encrypted secret delivery
    - req.agent typed context (no confused deputy)
    - Access reviewed quarterly
    - JIT/break-glass for admin
    - Documented offboarding for admin role removal
  Evidence:
    - Logs of every authentication
    - Code review trail in git
    - SOC 2 access review reports

CC6.2 (Logical access registration)
  Controls:
    - Identity registration via GitHub App OAuth + audience binding
    - Account creation tied to verified identity
    - Periodic identity revalidation (cadence per policy tier)
    - Webhook reconciliation for missed deliveries
  Evidence:
    - Registration logs (audit_log)
    - Revalidation cadence records
    - Webhook reconciliation runs

CC6.3 (Logical access modification/removal)
  Controls:
    - Key rotation: planned (with grace) + emergency (zero grace)
    - Account suspension/closure with cascade
    - Identity revocation with cascade to keys
    - All transitions immutably logged
  Evidence:
    - Audit log entries
    - State machine triggers in DB

CC6.6 (Logical credentials transmission)
  Controls:
    - Sealed-box (X25519 + ChaCha20-Poly1305) for secret delivery
    - TLS 1.3 minimum for transport
    - Audit log scrubbing prevents secret leak
  Evidence:
    - TLS config
    - Sealed-box implementation tests
    - Log scrubbing tests

CC7.1 (Detection: monitoring)
  Controls:
    - Prometheus metrics for all auth ops
    - SLO targets and burn-rate alerts
    - 12 named alert conditions (Section 7.5)
  Evidence:
    - Grafana dashboards
    - Alert manager configuration
    - On-call rotation

CC7.2 (Detection: anomaly)
  Controls:
    - Risk scoring per account
    - Behavior fingerprinting
    - Leaked-prefix scanner (GitHub search)
    - Webhook payload_hash mismatch detection
  Evidence:
    - Risk scoring computations
    - Detection alert logs

CC7.3 (Evaluation: incidents)
  Controls:
    - Runbooks RB-1 through RB-9
    - Incident severity matrix
    - Customer notification SLA (24h for breach affecting customer keys)
  Evidence:
    - Past incident reports
    - Customer notification templates

CC7.4 (Response: incidents)
  Controls:
    - Force-revoke key (RB-1)
    - Suspend account (RB-2)
    - Flush cache (RB-4)
    - Force webhook reconciliation (RB-9)
  Evidence:
    - Tabletop exercise results

CC7.5 (Recovery: incidents)
  Controls:
    - Restore from PITR
    - Identity unblock (RB-5)
    - DR drill quarterly
    - Post-incident review process
  Evidence:
    - Quarterly DR drill reports
    - Post-mortem documents

CC8.1 (Change management)
  Controls:
    - Forward-compatible migrations
    - Two-deploy destructive change protocol
    - Schema version pinned to lib version
    - Approvals required for git tags
    - Migration test on prod-shape data
  Evidence:
    - Migration logs in audit DB
    - Approval records for schema changes
    - Test results for forward-compatibility validation
    - Rollback evidence per migration

CC9.2 (Vendor risk)
  Controls:
    - Vendor inventory: GitHub, Anthropic (future), AWS, Postgres provider, Redis provider
    - DPAs/security reviews for each vendor
    - Annual review cadence
    - Subprocessor list maintained
    - Pinned dep versions; npm audit on every release
  Evidence:
    - Vendor list with DPAs filed
    - Annual review meeting notes
    - npm audit reports
```

## 9.2 GDPR

### 9.2.1 Legal basis

```yaml
gdpr_legal_basis:
  active_account_data:
    primary_basis: GDPR Article 6(1)(b)  # contract performance
    secondary_basis: GDPR Article 6(1)(f)  # legitimate interest (security)
  audit_log_retention:
    legal_obligation_basis: GDPR Article 17(3)(b)
    legal_claims_basis: GDPR Article 17(3)(e)
    security_legitimate_interest: GDPR Article 6(1)(f) + Recital 49
  documentation_required:
    LIA: docs/gdpr/lia.md          # legitimate interest assessment
    DPIA: docs/gdpr/dpia.md        # data protection impact assessment
    ROPA: docs/gdpr/ropa.md        # record of processing activities
```

### 9.2.2 Right to erasure

```
Erasure flow:
  1. SaaS owner calls DELETE /api/agent-auth/account/<id> with reason
  2. Active DB:
     a. Tier B: revoke all keys, mark identities revoked (cascade)
     b. Tier A: nullify PII fields (display_handle, identity.display_handle)
  3. Audit log: pseudonymize per jurisdiction (HMAC with subject-specific pepper)
  4. WORM audit: trigger crypto-erasure of subject's pepper key (KMS schedule_key_deletion)
  5. Backup tombstone: append to S3-stored erasure tombstone list
  6. Quarterly backup-purge job applies tombstones to backup retention

Statement to customer (DPO-reviewed):
  "Active systems are erased within 30 days. Audit logs containing pseudonymized
   references are retained for legal compliance (GDPR Article 17(3)(b)). After
   crypto-erasure of subject-specific pepper keys (30-day KMS deletion window),
   pseudonymized references in audit logs become unlinkable to the data subject.
   Pseudonymized data remains personal data per EDPB guidance until anonymity
   conditions are met. Lib does not represent crypto-erasure as GDPR Article 17
   complete erasure."
```

### 9.2.3 Crypto-erasure with per-subject KMS keys

```typescript
async function pseudonymizeWithSubjectKey(subjectId: string, value: string): Promise<string> {
  const kmsKeyAlias = `alias/agent-auth-subject-${hashSubject(subjectId)}`;
  const kmsKey = await kms.describeKey({ KeyId: kmsKeyAlias }).catch(async () => {
    // Auto-create on first use
    return await kms.createKey({
      Description: `agent-auth subject pseudonymization key`,
      KeyUsage: 'GENERATE_VERIFY_MAC',
      KeySpec: 'HMAC_256'
    });
  });
  const result = await kms.generateMac({
    KeyId: kmsKey.KeyId,
    Message: Buffer.from(value, 'utf8'),
    MacAlgorithm: 'HMAC_SHA_256'
  });
  return base64url(result.Mac);
}

async function eraseSubject(subjectId: string) {
  const kmsKeyAlias = `alias/agent-auth-subject-${hashSubject(subjectId)}`;
  const kmsKey = await kms.describeKey({ KeyId: kmsKeyAlias });
  await kms.scheduleKeyDeletion({
    KeyId: kmsKey.KeyId,
    PendingWindowInDays: 30
  });
  // After 30 days, key is irrevocably deleted.
  // Pseudonymized HMAC values become unlinkable.
  await db.query(
    `INSERT INTO agent_audit_log (ts, event_type, meta)
     VALUES (now(), 'subject_erasure_scheduled',
             jsonb_build_object('subject_hash', hash_subject($1),
                                'kms_key_id', $2,
                                'scheduled_at', now()))`,
    [subjectId, kmsKey.KeyId]
  );
}
```

### 9.2.4 Shared-pepper fallback

For high-volume SaaS where per-subject KMS keys are impractical:

```yaml
crypto_erasure:
  mode: shared_pepper             # alternative to per_subject
  pepper_storage: kms
  pepper_rotation_years: 1
  semantics: "minimization, not crypto-erasure"
  legal_framing: |
    Shared-pepper mode does NOT achieve GDPR Article 17 crypto-erasure for
    individual subjects. It provides minimization and pseudonymization with
    residual linkage risk. SaaS owner must:
      1. Document this choice in ROPA
      2. Inform data subjects of retention practices
      3. Not represent erasure-on-request as "complete erasure"
      4. Have DPO review and explicit sign-off
```

## 9.3 Supply chain security

```yaml
release_pipeline:
  signing:
    method: sigstore
    sbom_attestation: true        # SLSA L3 requires SBOM provenance
  publishing:
    npm_method: trusted_publishing_oidc   # GitHub Actions OIDC → npm; no NPM_TOKEN
    legacy_token_publishing: disabled
    provenance: enabled
    provenance_limitations_doc: docs/supply_chain/provenance_limits.md
  builds:
    lockfile: package-lock.json (committed)
    install_cmd: npm ci
    reproducible_target: SLSA L3
  github_actions:
    pin_by_sha: true                       # actions/checkout@SHA, never @v4
    require_phishing_resistant_mfa: true   # passkey/hardware key for maintainers
  scanning:
    secret_scanning: github_native + gitleaks
    dependency_review: github_dependency_review_action
    openssf_scorecard: enabled
    minimum_scorecard: 8.5
  release_approval:
    git_tags_protected: true
    require_two_reviewers: true
    require_environment_approval: production
  consumer_verification:
    method: npm-provenance-OR-cosign-verify-blob-attestation
    docs: README.md#verifying-releases
  sbom_format: CycloneDX
```

### 9.3.1 Verifying releases

Consumers verify signed releases:

```bash
# Method 1: npm provenance (preferred)
npm install agent-auth
npm audit signatures   # checks Sigstore provenance

# Method 2: cosign verify-blob-attestation (for non-npm distribution)
cosign verify-blob-attestation \
  --bundle agent-auth-1.0.0.tgz.sigstore \
  agent-auth-1.0.0.tgz
```


---

# Part X — API Reference

## 10.1 Public endpoints

### POST /api/agent-auth/begin-registration

```
Request:
  Content-Type: application/json
  X-Request-Id: <UUID> (optional; generated if missing)

  {
    "provider": "github_app",
    "intent": "register" | "recover" | "add_key" | "revalidate",
    "label": "claude-code-laptop" (optional, ≤64 chars),
    "use_device_flow": false (optional, default false),
    "client_pubkey": "<32 bytes base64url>",
    "account_id": "<UUID>" (required if intent=recover or revalidate)
  }

Response 200 (browser flow):
  {
    "poll_token": "pak_...",       (or pkr_/pad_/pav_ per intent)
    "challenge_url": "https://github.com/login/oauth/authorize?...",
    "expires_at": "2026-04-30T12:05:00Z",
    "poll_interval_seconds": 2
  }

Response 200 (device flow):
  {
    "poll_token": "...",
    "device_code_info": {
      "user_code": "WDJB-MJHT",
      "verification_uri": "https://github.com/login/device",
      "verification_uri_complete": "...",
      "expires_in_seconds": 900,
      "poll_interval_seconds": 5
    },
    "expires_at": "2026-04-30T12:15:00Z"
  }

Errors:
  400 invalid_provider
  400 invalid_label
  400 invalid_intent
  400 invalid_client_pubkey (not 32 bytes or not valid base64url)
  400 missing_account_id_for_intent (recover/revalidate require account_id)
  404 account_not_found (recover/revalidate)
  410 account_closed
  403 account_suspended_unsuspend_first
  429 too_many_registrations (per-IP limit)
  503 idp_circuit_open (GitHub circuit breaker open)
```

### POST /api/agent-auth/registration-status

```
Request:
  { "poll_token": "pak_..." | "pad_..." }

Response 200 (pending):
  { "status": "pending" }

Response 200 (completed):
  {
    "status": "completed",
    "account_id": "<UUID>",
    "encrypted_payload": "<base64url sealed-box ciphertext>",
    "is_first_key": true | false
  }

Response 200 (failed):
  {
    "status": "failed",
    "code": "user_denied" | "expired_token" | "access_denied" | "...",
    "message": "Human-readable detail"
  }

Errors:
  410 session_expired
  410 invalid_kind (token kind doesn't match endpoint)
  400 invalid_poll_token
```

### POST /api/agent-auth/recover-account-status

Same as /registration-status but accepts only `pkr_` poll tokens.

### POST /api/agent-auth/rotate-key

```
Request:
  Authorization: Bearer agk_<id>_<secret>
  Idempotency-Key: <UUID>
  { "grace_seconds": 3600, "reason": "scheduled_rotation" }

Response 200:
  {
    "old_key": {
      "key_id": "agk_aB1cD2eF",
      "rotated_at": "2026-04-30T12:00:00Z",
      "grace_expires_at": "2026-04-30T13:00:00Z" | null
    },
    "new_key": {
      "key_id": "agk_xK7mN9pQ",
      "secret": "<full key, shown once>",
      "prefix": "abcdefgh",
      "scopes": ["read", "self:rotate"],
      "tier": "warm"
    }
  }

Errors:
  401 invalid_key
  403 insufficient_scope (key lacks 'self:rotate')
  409 already_rotating
  409 idempotency_mismatch
  425 idempotency_in_flight
  503 durability_unconfirmed (Tier B for emergency rotation only)
  503 audit_unavailable (Tier B for emergency rotation only)
```

### POST /api/agent-auth/revoke

```
Request:
  Authorization: Bearer <key>
  Idempotency-Key: <UUID>
  { "key_id": "agk_aB1cD2eF", "reason": "lost_device" }

Response 200:
  { "revoked_at": "2026-04-30T12:00:00Z", "key_id": "agk_aB1cD2eF" }

Errors:
  401 invalid_key
  403 insufficient_scope (must have 'self:revoke' or 'admin:keys')
  404 key_not_found
  409 already_revoked
  503 durability_unconfirmed
```

### POST /api/agent-auth/recover-account

Initiate recovery; same body as /begin-registration with intent='recover'.

### POST /api/agent-auth/recover-account-confirm/<token>

Owner-side approval webhook target. Accepts SaaS owner's decision.

```
Request:
  Authorization: Bearer <recovery_webhook_token>  (SaaS-side secret)
  Idempotency-Key: <UUID>
  { "approve": true | false, "reason": "manual_review_passed" }

Response 200:
  {
    "request_id": "<UUID>",
    "decision": "approved" | "denied",
    "decision_at": "2026-04-30T12:00:00Z"
  }
```

### GET /api/agent-auth/keys

```
Request:
  Authorization: Bearer <key with 'admin:keys' scope>

Response 200:
  {
    "keys": [
      {
        "key_id": "agk_...",
        "prefix": "abcdefgh",
        "label": "claude-code-laptop",
        "scopes": ["read", "self:rotate"],
        "tier": "cold",
        "rotation_state": "active",
        "created_at": "2026-04-30T12:00:00Z",
        "last_used_at": "2026-04-30T13:00:00Z" | null,
        "expires_at": null
      }
    ]
  }
```

### GET /.well-known/agent-auth

```
Response 200:
  {
    "version": "v1",
    "endpoints": {
      "begin_registration": "https://saas.com/api/agent-auth/begin-registration",
      "registration_status": "https://saas.com/api/agent-auth/registration-status",
      "rotate_key": "https://saas.com/api/agent-auth/rotate-key",
      "revoke": "https://saas.com/api/agent-auth/revoke",
      "recover_account": "https://saas.com/api/agent-auth/recover-account"
    },
    "supported_providers": [
      {
        "name": "github_app",
        "supports_browser_flow": true,
        "supports_device_flow": true,
        "default_assurance": "medium"
      }
    ],
    "available_scopes": ["read", "write", "admin:keys", "self:rotate", "self:revoke"],
    "rate_limit_headers": {
      "remaining": "X-RateLimit-Remaining",
      "reset": "X-RateLimit-Reset",
      "limit": "X-RateLimit-Limit",
      "retry_after": "Retry-After"
    },
    "registration_max_age_seconds": 300,
    "min_revocation_latency_seconds": 100,
    "barrier_mode": "strict_uncached" | "bounded_stale_1s",
    "documentation_url": "https://saas.com/docs/agent-auth"
  }
```

## 10.2 Internal endpoints

### GET /api/agent-auth/callback/:provider

Browser redirect target for OAuth. Internal use only by upstream provider.

### POST /api/agent-auth/webhooks/:provider

Webhook endpoint for upstream provider events. Lib handles HMAC verification.

### GET /api/agent-auth/healthz

```
Response 200:
  {
    "status": "healthy",
    "version": "1.0.0",
    "timeline_id": 1,
    "barrier_lsn": "16/B374D848",
    "redis_quorum_acks": 1,
    "circuit_breakers": { "github_app": "closed" }
  }

Response 503:
  {
    "status": "unhealthy",
    "reasons": ["timeline_mismatch", "redis_unreachable"]
  }
```

## 10.3 Error response format

All errors:

```json
{
  "error": {
    "code": "<machine-readable enum>",
    "message": "<human-readable detail>",
    "request_id": "<UUID>",
    "documentation_url": "https://saas.com/docs/agent-auth/errors#<code>"
  }
}
```

## 10.4 Standard error codes

```
400 invalid_request, invalid_provider, invalid_label, invalid_intent,
    invalid_client_pubkey, invalid_poll_token, missing_account_id_for_intent
401 invalid_key, key_revoked, key_rotated, account_suspended,
    identity_revoked, rotation_grace_expired, key_expired,
    revalidation_required (with WWW-Authenticate header), invalid_secret
403 insufficient_scope, account_suspended_unsuspend_first,
    identity_account_mismatch, identity_blocked
404 account_not_found, key_not_found, identity_not_recognized_for_account
409 already_rotating, already_revoked, account_exists,
    idempotency_mismatch, idempotency_key_payload_mismatch,
    identity_blocked_admin_unblock_required
410 account_closed, session_expired, invalid_kind, already_consumed
425 idempotency_in_flight
429 too_many_requests, too_many_registrations
500 internal_error
503 durability_unconfirmed, durability_unavailable, audit_unavailable,
    idp_circuit_open, region_replication_stale, failover_in_progress,
    idempotency_unknown_outcome, idempotency_manual_required
```

## 10.5 Response headers

Every authenticated response includes:

```
X-Request-Id: <UUID>
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 42 (seconds until full reset)
Retry-After: 13 (only on 429/503)
```

Deprecation responses include:

```
Deprecation: @1730419200            # RFC 9745
Sunset: Sat, 01 Apr 2027 00:00:00 GMT  # RFC 8594
Link: <https://saas.com/docs/v2-migration>; rel="deprecation"
```


---

# Part XI — Implementation Plan

## 11.1 Repository structure

```
agent-auth/
├── package.json
├── tsconfig.json
├── .npmrc                              # registry, provenance config
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                      # lint, type-check, test
│   │   ├── release.yml                 # OIDC trusted publishing
│   │   └── security.yml                # Scorecard, secret scan
│   ├── CODEOWNERS
│   └── dependabot.yml
├── src/
│   ├── index.ts                        # main lib export
│   ├── config.ts                       # AgentAuthConfig type + defaults
│   ├── errors.ts                       # AgentAuthError, ServiceUnavailableError, ...
│   ├── routes/
│   │   ├── begin-registration.ts
│   │   ├── registration-status.ts
│   │   ├── recover-account.ts
│   │   ├── rotate-key.ts
│   │   ├── revoke.ts
│   │   ├── keys.ts
│   │   ├── well-known.ts
│   │   ├── healthz.ts
│   │   ├── callback.ts                 # internal OAuth callback
│   │   └── webhooks.ts                 # internal webhook receiver
│   ├── middleware/
│   │   ├── validate-key.ts             # main validation middleware
│   │   ├── rate-limit.ts               # GCRA wrapper
│   │   └── idempotency.ts              # Tier B idempotency wrapper
│   ├── identity/
│   │   ├── provider.ts                 # IdentityProvider interface
│   │   ├── github-app/
│   │   │   ├── browser-flow.ts
│   │   │   ├── device-flow.ts
│   │   │   ├── webhook.ts
│   │   │   └── reconcile.ts
│   │   ├── anthropic-api-key.ts        # secondary, low-assurance
│   │   └── anthropic-attestation.ts    # future
│   ├── crypto/
│   │   ├── sealed-box.ts
│   │   ├── hmac-pepper.ts
│   │   ├── audit-hash.ts
│   │   ├── pkce.ts
│   │   └── kms.ts                      # AWS/GCP KMS wrapper
│   ├── storage/
│   │   ├── postgres-adapter.ts
│   │   ├── redis-adapter.ts
│   │   ├── kms-adapter.ts
│   │   └── s3-worm-adapter.ts
│   ├── distributed/
│   │   ├── revocation-epoch.ts
│   │   ├── revocation-barrier.ts
│   │   ├── tier-b-commit.ts
│   │   └── failover.ts
│   ├── reliability/
│   │   ├── gcra.ts                     # plus Lua script as resource
│   │   ├── idempotency.ts
│   │   ├── circuit-breaker.ts
│   │   └── outbox.ts
│   ├── audit/
│   │   ├── db-writer.ts                # in-DB hash chain
│   │   ├── worm-writer.ts              # S3 Object Lock
│   │   ├── scrubber.ts                 # log/audit scrubbing rules
│   │   └── verify-chain.ts             # hourly tamper detection
│   ├── jobs/
│   │   ├── reaper.ts                   # expire registration sessions
│   │   ├── reconcile-redis.ts          # Redis SET drift
│   │   ├── reconcile-idempotency.ts    # unknown state observer
│   │   ├── webhook-replay.ts           # GitHub delivery polling
│   │   ├── audit-verifier.ts           # hash chain check
│   │   └── outbox-flusher.ts
│   ├── admin/
│   │   ├── cli.ts
│   │   ├── webauthn.ts                 # FIDO2 / WebAuthn auth
│   │   ├── two-person.ts
│   │   └── jit-rbac.ts
│   ├── agent-context.ts                # AgentContext type + builder
│   └── types.ts                        # shared types
├── schema/
│   ├── migrations/
│   │   ├── 0001_init.sql
│   │   ├── 0002_audit_partitions.sql
│   │   └── ...
│   └── seed.sql
├── scripts/
│   ├── pre-promotion-checks.sh
│   ├── post-promotion-reset.sh
│   └── readiness-probe.sh
├── examples/
│   ├── express-integration.ts
│   ├── hono-integration.ts
│   ├── nextjs-integration.ts
│   └── agent-sdk-typescript.ts
├── test/
│   ├── unit/
│   ├── integration/                    # uses real Postgres + Redis
│   └── chaos/                          # Toxiproxy scenarios
├── docs/
│   ├── runbooks/
│   │   ├── RB-1-revoke-key.md
│   │   ├── RB-2-suspend-account.md
│   │   ├── ...
│   │   └── RB-9-webhook-backfill.md
│   ├── gdpr/
│   │   ├── lia.md
│   │   ├── dpia.md
│   │   ├── ropa.md
│   │   └── retention_legal_basis.md
│   ├── adr/                            # architecture decision records
│   └── supply_chain/
└── README.md
```

## 11.2 Build order (milestones)

### Milestone M1: Core data model + validation (1 weekend)

- [ ] Postgres schema: 0001_init.sql with all tables + constraints
- [ ] PostgresAdapter wrapper
- [ ] HMAC + KMS pepper key validation
- [ ] req.agent context builder
- [ ] Express + Hono middleware adapters
- [ ] Unit tests for validation logic

**Deliverable**: a SaaS can mount middleware and validate manually-inserted keys.

### Milestone M2: GitHub App registration (1 weekend)

- [ ] GitHub App provider implementation (browser flow only)
- [ ] /begin-registration + /callback + /registration-status endpoints
- [ ] Sealed-box delivery via libsodium
- [ ] agent_registration_sessions schema + reaper job
- [ ] PKCE state binding + nonce single-use
- [ ] Integration test: full registration end-to-end

**Deliverable**: a SaaS can let agents register accounts via GitHub OAuth.

### Milestone M3: Rotation + Revocation + Idempotency (1 weekend)

- [ ] /rotate-key (planned grace + emergency)
- [ ] /revoke
- [ ] Idempotency framework (two-phase + observer)
- [ ] revocation_epoch + revocation_barrier
- [ ] Tier B commit wrapper
- [ ] Cache invalidation pipeline (DEL + PUBLISH)

**Deliverable**: rotation and revocation work atomically; observer reconciles unknowns.

### Milestone M4: Webhooks + reconciliation (0.5 weekend)

- [ ] /webhooks/github_app endpoint with HMAC verify-first ordering
- [ ] webhook deduplication via X-GitHub-Delivery
- [ ] Webhook replay polling job (within 3-day window)
- [ ] Cascade identity revocation → key revocation

**Deliverable**: GitHub revocations reach our system.

### Milestone M5: Rate limiting + observability (0.5 weekend)

- [ ] GCRA Lua script + Redis storage
- [ ] Multi-dimensional rate limit middleware
- [ ] Prometheus metrics emitter
- [ ] Structured logging with scrubber
- [ ] OpenTelemetry tracing

**Deliverable**: production-grade observability + abuse protection.

### Milestone M6: Recovery + multi-region (1 weekend)

- [ ] /recover-account flow + owner approval webhook
- [ ] Recovery state machine (active-only invariant)
- [ ] LSN barrier protocol (post-commit barrier capture)
- [ ] Cross-region validation with authoritative barrier read
- [ ] Failover readiness gate (post-promotion script)

**Deliverable**: multi-region active-passive with correct revocation visibility.

### Milestone M7: Audit + compliance (0.5 weekend)

- [ ] In-DB hash chain (trigger + verifier job)
- [ ] S3 Object Lock WORM writer with outbox pattern
- [ ] Log scrubber (allow-list, entropy detection)
- [ ] Quarterly DR drill script

**Deliverable**: SOC 2 / GDPR ready audit trail.

### Milestone M8: Admin CLI + supply chain (0.5 weekend)

- [ ] WebAuthn-gated admin CLI
- [ ] All RB-1 through RB-9 commands
- [ ] Two-person rule enforcement
- [ ] JIT RBAC
- [ ] Sigstore signing in release pipeline
- [ ] OIDC trusted publishing setup

**Deliverable**: production-ready release pipeline.

### Total: ~6 weekends with AI-agent coding

## 11.3 Tech stack

### 11.3.1 Runtime + language

| | Choice | Rationale |
|---|---|---|
| Runtime | **Node.js 20+ LTS** primary; Bun 1.x compatible | Most SaaS run Node in prod; lib uses standard Node APIs so Bun also works for consumers who prefer it |
| Source | **TypeScript 5.4+ strict** | Spec assumes TS throughout; same generation as Better Auth / Clerk / Linear; no `any` allowed in security paths |
| Build | **tsup** (dual ESM/CJS output) | Most modern, fast, both module systems for compat |
| Module format | ESM primary, CJS fallback | npm + Node 20 ESM works; CJS for legacy consumers |

### 11.3.2 Core dependencies

```json
{
  "name": "agent-auth",
  "version": "1.0.0",
  "engines": { "node": ">=20.0.0" },
  "dependencies": {
    "libsodium-wrappers": "^0.7.13",
    "pg": "^8.11.0",
    "ioredis": "^5.3.0",
    "@aws-sdk/client-kms": "^3.0.0",
    "@aws-sdk/client-s3": "^3.0.0",
    "@octokit/auth-app": "^7.0.0",
    "zod": "^3.22.0",
    "pino": "^9.0.0",
    "@opentelemetry/api": "^1.7.0",
    "commander": "^12.0.0"
  },
  "peerDependencies": {
    "express": "^4.0.0",
    "hono": "^4.0.0",
    "fastify": "^5.0.0",
    "next": "^15.0.0"
  },
  "peerDependenciesMeta": {
    "express": { "optional": true },
    "hono":    { "optional": true },
    "fastify": { "optional": true },
    "next":    { "optional": true }
  },
  "devDependencies": {
    "typescript": "^5.4.0",
    "tsup": "^8.0.0",
    "vitest": "^1.0.0",
    "testcontainers": "^10.0.0",
    "toxiproxy-node-client": "^2.0.0",
    "fast-check": "^3.0.0",
    "@types/node": "^20.0.0",
    "eslint": "^9.0.0",
    "@typescript-eslint/eslint-plugin": "^7.0.0",
    "@typescript-eslint/parser": "^7.0.0"
  }
}
```

Pin versions exact (no `^`) in lockfile before release. `npm ci` only.

### 11.3.3 Why each dep was chosen

| Dep | Purpose | Why this and not X |
|---|---|---|
| **libsodium-wrappers** | sealed-box, HMAC, constant-time compare | Industry-standard crypto; `crypto_box_seal` is exactly what we need for ADR-004 (anonymous encryption to recipient public key). NOT `node:crypto` for sealed-box because Node has no equivalent primitive. |
| **pg** | Postgres driver | Battle-tested, official, supports `pg_lsn`, listen/notify, prepared statements. NOT `postgres.js` (less battle-tested for our LSN+partition use), NOT Drizzle/Prisma (lib should not force ORM choice on consumers). |
| **ioredis** | Redis client | Lua eval support + Cluster + Sentinel + WAIT command — all required by §5.2-5.3. NOT `node-redis` (Lua support thinner, cluster handling worse). |
| **@aws-sdk/client-kms** | HMAC pepper + sealed box keys | Standard AWS SDK v3, modular import keeps bundle small. KMS `GenerateMac` is core to ADR-003 (HMAC-SHA256 verifier). |
| **@aws-sdk/client-s3** | WORM audit log | Object Lock COMPLIANCE mode requires SDK; S3 client is the standard. |
| **@octokit/auth-app** | GitHub App JWT signing | Official Octokit auth strategy for GitHub Apps; handles JWT minting + token caching for app-level operations (webhook redelivery polling). |
| **zod** | Config + input schema validation | Lightweight runtime validation; SaaS-side AgentAuthConfig validated at init; webhook bodies + API request bodies validated at boundary. NOT `class-validator` (decorators add complexity). |
| **pino** | Structured logging | ~5x faster than winston; JSON output by default; child logger pattern fits request-scoped fields. |
| **@opentelemetry/api** | Distributed tracing | Standard tracing API; consumers BYO exporter (OTLP, Jaeger, Datadog). API only — no SDK forced. |
| **commander** | Admin CLI | Standard, mature, supports nested subcommands + WebAuthn integration patterns. |

### 11.3.4 Framework adapters (peer dependencies)

The lib provides thin adapters (~100 lines each). Consumer installs only the framework they use:

```typescript
// Express
import { agentAuth, expressAdapter } from 'agent-auth';
const agents = agentAuth({ ... });
app.use('/api/agent-auth', expressAdapter(agents).routes());
app.use('/api/agent/v1', expressAdapter(agents).middleware, agentRoutes);

// Hono
import { honoAdapter } from 'agent-auth';
app.route('/api/agent-auth', honoAdapter(agents).routes());
app.use('/api/agent/v1/*', honoAdapter(agents).middleware);

// Fastify
import { fastifyAdapter } from 'agent-auth';
fastify.register(fastifyAdapter(agents).plugin, { prefix: '/api/agent-auth' });

// Next.js App Router
// app/api/agent-auth/[...slug]/route.ts
import { nextRouteHandler } from 'agent-auth';
export const { GET, POST } = nextRouteHandler(agents);
```

### 11.3.5 Storage requirements (consumer-deployed, not lib deps)

| | Minimum version | Why |
|---|---|---|
| PostgreSQL | **14+** | Needs `gen_random_uuid()`, declarative partition, `pg_lsn` type, `pg_is_in_recovery()`, `pg_current_wal_insert_lsn()` |
| Redis | **7+** | Needs `WAIT` command (replica quorum), `SET NX EX` (atomic nonce), Pub/Sub, Lua eval |
| KMS | AWS KMS / GCP Cloud KMS / Azure Key Vault | `GENERATE_MAC` (HMAC), envelope encryption for device codes |
| Object storage | S3 with Object Lock COMPLIANCE OR GCS with Object Holds OR Azure immutable Blob | WORM audit log retention |

Lib provides adapters: `awsKmsAdapter`, `gcpKmsAdapter`, `azureKeyVaultAdapter`. Consumer plugs in.

### 11.3.6 Tooling

| Task | Choice | Notes |
|---|---|---|
| Package manager | **npm** | trusted publishing OIDC integrates best; `npm ci` enforces lockfile |
| Build | **tsup** | Dual ESM/CJS, source maps, `--minify` for prod |
| Test | **vitest** | ~3x faster than Jest, native ESM, watch mode reliable |
| Property-based test | **fast-check** | Industry standard for JS/TS |
| Container test | **testcontainers** | Spins Postgres / Redis / LocalStack for integration tests |
| Chaos | **toxiproxy-node-client** | Network partition, latency injection per §12.4 |
| CLI | **commander** | Mature, supports our admin CLI patterns |
| Version mgmt | **changesets** | Semver discipline, changelog generation |
| Release | **GitHub Actions + Sigstore + npm OIDC** | SLSA L3 target |
| Lint | **eslint + @typescript-eslint** | Custom rules: forbid `req.user` access in agent routes (§6.3); forbid `.split('_')` on key parsing (§2.2) |

### 11.3.7 What we deliberately DON'T use

| Rejected | Why |
|---|---|
| **Argon2id** for API key hashing | API keys are 256-bit random, not low-entropy passwords. ADR-003 picked HMAC + KMS pepper. |
| **node-redis** | Worse Lua + Cluster support than ioredis; we need both. |
| **postgres.js** (porsager/postgres) | Cleaner API but less battle-tested for our LSN/partition use; pg is safer. |
| **Drizzle / Prisma / TypeORM** | Lib should not force ORM choice on consumers. Raw SQL via pg keeps adapter shape minimal. |
| **Knex** migrations | Heavy; we use lightweight `schema/migrations/*.sql` runner. |
| **Better Auth fork** | 80% human-flow code we don't need; would carry maintenance burden + dilute narrative. ADR-002. |
| **Bun-only runtime** | Lib is a library; consumers run Node in production. Bun-compatible build is enough. |
| **Custom crypto** | Sealed box, HMAC, X25519 — all libsodium primitives. No bespoke. |
| **Go / Rust** | User's Go experience light; OSS target audience (Anthropic / Vercel / Supabase / Inngest) is TS-heavy. Rust appropriate for sqlv-style tooling, not auth library. |

### 11.3.8 Project total size estimate

```
src/                    ~1,500-2,000 LoC (TypeScript)
test/unit/              ~600 LoC
test/integration/       ~500 LoC
test/chaos/             ~200 LoC
schema/migrations/      ~800 LoC SQL
examples/               ~300 LoC
docs/runbooks/          ~500 LoC markdown
docs/gdpr/              ~200 LoC markdown
docs/adr/               ~300 LoC markdown
─────────────────────────────────────
Total OSS repo:         ~5,000 LoC code + ~5,000 LoC docs/spec
```

Roughly an order of magnitude smaller than Better Auth (~30k LoC) because scope is narrow (agent-only, no human flows).

## 11.4 Configuration interface

```typescript
interface AgentAuthConfig {
  internal_secret: Buffer;                              // 256-bit, required

  identity_providers: IdentityProvider[];

  storage: {
    postgres: PostgresAdapter;
    redis: RedisAdapter;
    kms: KmsAdapter;
    audit_worm?: S3WormAdapter;                         // optional but recommended
  };

  rate_limit?: RateLimitConfig;
  audit_log?: AuditLogConfig;
  recover_account?: RecoverAccountConfig;
  reconciliation?: ReconciliationConfig;
  revalidation?: RevalidationConfig;
  multi_region?: MultiRegionConfig;
  validation?: ValidationConfig;
  failover?: FailoverConfig;
  observability?: ObservabilityConfig;

  clock?: Clock;                                        // for testing
}
```

Default values are explicit in `src/config.ts` with comments explaining each.

## 11.5 Database role setup (deployment prerequisite)

```sql
-- One-time setup by DBA before lib deployment

CREATE ROLE agent_auth_app NOLOGIN;
CREATE ROLE agent_auth_admin NOLOGIN;
CREATE ROLE agent_auth_readonly NOLOGIN;

-- Migration role (used only by `agent-auth migrate`)
CREATE ROLE agent_auth_migrator NOLOGIN;
GRANT CREATE ON SCHEMA public TO agent_auth_migrator;

-- App role: pooled connections inherit this
CREATE USER agent_auth_app_user PASSWORD '<from secret>';
GRANT agent_auth_app TO agent_auth_app_user;

-- Admin role: separate user, MFA-gated
CREATE USER agent_auth_admin_user PASSWORD '<from secret>';
GRANT agent_auth_admin TO agent_auth_admin_user;
```


---

# Part XII — Testing Strategy

## 12.1 Test pyramid

```
                  ┌─────────────┐
                  │ Chaos tests │     ~10 scenarios
                  └─────────────┘
                ┌──────────────────┐
                │ Integration tests │   ~100 tests
                │ (real Postgres+   │
                │  Redis+localstack)│
                └──────────────────┘
              ┌────────────────────────┐
              │     Unit tests         │   ~500 tests
              │  (pure functions,      │
              │  isolated components)  │
              └────────────────────────┘
```

## 12.2 Required unit tests

```typescript
// src/crypto/sealed-box.test.ts
describe('sealed_box', () => {
  test('round-trip encrypt/decrypt')
  test('decryption with wrong private key fails')
  test('decryption of corrupted ciphertext fails')
  test('forward secrecy: cannot decrypt with derived server key')
});

// src/crypto/hmac-pepper.test.ts
describe('hmac_pepper', () => {
  test('HMAC verification constant time')
  test('multi-pepper-version verification during rotation window')
});

// src/reliability/gcra.test.ts
describe('gcra', () => {
  test('cost=1: 10 immediate accepts then 11th rejects with retry_after≈6s for burst=10/60s')
  test('cost==burst: 1 immediate accept, full reset window before next')
  test('cost > burst: rejects with error_reply')
  test('after reset window: full burst available again')
  test('remaining_units never negative')
});

// src/middleware/validate-key.test.ts
describe('validate_key', () => {
  test('rotation_state=active: accept')
  test('rotation_state=revoked: reject 401 key_revoked')
  test('rotation_state=rotating, grace not expired: accept')
  test('rotation_state=rotating, grace expired: reject 401 rotation_grace_expired + auto-transition')
  test('rotation_state=rotated: reject 401 key_rotated')
  test('account_status=suspended: reject 401 account_suspended')
  test('issuing_identity_status=revoked: reject 401 identity_revoked')
  test('expires_at < now: reject 401 key_expired')
  test('invalid_secret: reject 401 invalid_secret')
});

// src/distributed/revocation-barrier.test.ts
describe('revocation_barrier', () => {
  test('barrier monotonic: GREATEST(old, new)')
  test('post-commit LSN captured after sync replication ack')
  test('timeline_id mismatch rejects validation in secondary')
  test('replay LSN < barrier LSN: route to primary or fail closed')
  test('replay LSN >= barrier LSN: trust local read')
});

// src/reliability/idempotency.test.ts
describe('idempotency', () => {
  test('first call: pending → completed, returns result')
  test('retry with same key+hash: returns cached completed response')
  test('retry with same key, different hash: 409 idempotency_key_payload_mismatch')
  test('Tier B timeout: state=unknown, observer reconciles to completed')
  test('Tier B timeout, resource not found: state=unknown → failed')
  test('5 reconcile attempts: state=manual_required, page on-call')
  test('terminal state immutable: cannot regress completed → unknown')
  test('admin override allowed for completed → failed (audit logged)')
});

// src/audit/scrubber.test.ts
describe('audit_scrubber', () => {
  test('redacts agk_ keys in plain text')
  test('redacts agk_ keys in URL query string (?token=agk_...)')
  test('redacts agk_ keys in JSON-stringified value')
  test('redacts in Authorization header value')
  test('UUIDs not redacted (allow-list)')
  test('high-entropy 32+ char tokens redacted')
  test('truncates strings > 1024 chars')
  test('depth limit enforced')
  test('non-allowlisted JSONB keys removed')
});
```

## 12.3 Required integration tests

Use Testcontainers for Postgres + Redis + LocalStack (S3/KMS).

```typescript
// test/integration/registration.test.ts
test('full GitHub App registration flow')
test('duplicate registration returns 409 with use_recover hint')
test('replay /register with same identity returns 409')
test('expired session: 410 session_expired')
test('client_pubkey size != 32 bytes: 400')
test('invalid PKCE verifier: 400 with audit log entry')

// test/integration/rotation.test.ts
test('planned rotation with grace=3600: old key valid during grace')
test('planned rotation: grace expires, old key rejected')
test('emergency rotation: old key rejected immediately')
test('concurrent rotations on same predecessor: one succeeds, other 409')
test('idempotent retry with same Idempotency-Key returns same result')

// test/integration/revocation.test.ts
test('revoke with Tier B sync: visible in next validation')
test('cascade: identity revoked → all keys revoked')
test('cascade: account suspended → all keys revoked')
test('webhook revocation: cascade applied')

// test/integration/multi-region.test.ts
test('secondary region: replay LSN < barrier rejects validation')
test('secondary region: replay LSN >= barrier accepts')
test('failover: timeline mismatch rejects until reset script runs')
test('post-promotion script: barrier reset, service resumes')

// test/integration/cache.test.ts
test('revoke: epoch bumped, validation falls through to Postgres')
test('cache hit with current epoch: served from cache')
test('cache hit with stale epoch: fetches fresh from DB')
test('Redis down: validations fall through to Postgres directly')

// test/integration/webhook.test.ts
test('valid HMAC + new delivery_id: processed')
test('invalid HMAC: 401, no DB write')
test('valid HMAC, duplicate delivery_id, same payload: idempotent no-op')
test('valid HMAC, duplicate delivery_id, DIFFERENT payload: alert + no overwrite')
test('webhook replay job: redelivers failed deliveries within 72h window')

// test/integration/recovery.test.ts
test('recover with fresh OAuth: identity reactivated, new key issued, old keys stay revoked')
test('recover account.status=suspended: 403 unsuspend_first')
test('recover account.status=closed: 410')
test('recover with manually revoked identity: 409 admin_unblock_required')
test('owner approval webhook required: waits for confirm before issuing key')
test('approval timeout (24h): session marked failed')
```

## 12.4 Chaos tests (Toxiproxy)

```typescript
// test/chaos/redis-partition.test.ts
test('Redis network partition: validations fall through to Postgres')
test('Redis recovers: cache repopulates organically')

// test/chaos/postgres-standby-down.test.ts
test('Tier B with sync standby unreachable: 503 durability_unavailable')
test('Async replica down: secondary region routes to primary')

// test/chaos/clock-skew.test.ts
test('±1s clock skew: webhook within tolerance accepted')
test('±5min skew: outside tolerance rejected')

// test/chaos/redis-split-brain.test.ts
test('Redis epoch update: monotonic via Lua MAX, no decrease')

// test/chaos/concurrent-rotation.test.ts
test('100 concurrent /rotate-key on same key: exactly 1 succeeds')

// test/chaos/audit-worm-down.test.ts
test('S3 unreachable during Tier B: 503 audit_unavailable')
test('S3 recovers: outbox flushes pending events')
```

## 12.5 Property-based tests

```typescript
// Using fast-check
test.prop('idempotency state transitions never regress',
  arb_random_state_sequence,
  (sequence) => {
    const final = applyTransitions(sequence);
    if (sequence.includes('completed')) {
      expect(final).toBeOneOf(['completed']);
    }
    if (sequence.includes('failed')) {
      expect(final).toBeOneOf(['failed']);
    }
    expect(final).not.toBe('pending');  // always reaches terminal eventually
  });

test.prop('GCRA: total accepts in window <= burst capacity',
  arb_gcra_load_pattern,
  (loadPattern) => {
    const accepted = simulateGCRA(loadPattern);
    expect(accepted.length).toBeLessThanOrEqual(loadPattern.burst);
  });
```

## 12.6 Performance benchmarks (gated in CI)

```bash
# bench/validation.bench.ts
# Validates 10K cached keys; reports P50, P99
# Threshold: regression > 20% blocks merge

npm run bench

Output expected:
  validation_cache_hit_same_az:    P50=1.2ms  P99=4.8ms  (target P50<5ms, P99<50ms) ✓
  validation_cache_miss_with_hmac: P50=12ms   P99=45ms   (target P50<30ms, P99<100ms) ✓
  registration_e2e_excluding_idp:  P50=180ms  P99=420ms  (target P50<200ms) ✓
  webhook_processing_p50:          P50=85ms   P99=210ms  (target P50<100ms) ✓
  rate_limit_check:                P50=0.3ms  P99=1.2ms
```

## 12.7 Pre-release checklist

```yaml
release_checklist:
  - [ ] All unit tests pass (npm test)
  - [ ] All integration tests pass (npm run test:integration)
  - [ ] All chaos tests pass (npm run test:chaos)
  - [ ] Property-based tests pass (1000 iterations)
  - [ ] Benchmarks meet targets (npm run bench)
  - [ ] Schema migration tested forward + backward
  - [ ] OpenSSF Scorecard >= 8.5
  - [ ] npm audit signatures: 0 issues
  - [ ] OWASP API Top 10 self-review
  - [ ] All RT-* threats have integration test coverage
  - [ ] Audit hash chain verifier passes 30-day historical replay
  - [ ] DR drill on staging: RTO < 1h confirmed
  - [ ] Documentation updated (SPEC.md, runbooks, migration guide)
  - [ ] CHANGELOG entry with security implications noted
  - [ ] Two reviewers approved release tag
  - [ ] Sigstore signing succeeded
```


---

# Part XIII — Deployment Topology

## 13.1 Kubernetes manifests (reference)

### 13.1.1 App deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-auth-app
spec:
  replicas: 3
  selector:
    matchLabels: { app: agent-auth }
  template:
    metadata:
      labels: { app: agent-auth }
    spec:
      serviceAccountName: agent-auth-sa
      containers:
      - name: app
        image: my-registry/saas-app:1.0.0   # SaaS owner's image with agent-auth lib mounted
        env:
        - name: AGENT_AUTH_INTERNAL_SECRET
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: internal_secret } }
        - name: AGENT_AUTH_DATABASE_URL
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: database_url } }
        - name: AGENT_AUTH_REDIS_URL
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: redis_url } }
        - name: GH_CLIENT_SECRET
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: gh_client_secret } }
        - name: GH_WEBHOOK_SECRET
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: gh_webhook_secret } }
        - name: GH_APP_PRIVATE_KEY
          valueFrom: { secretKeyRef: { name: agent-auth-secrets, key: gh_app_private_key } }
        - name: AWS_REGION
          value: us-east-1
        # KMS access via IRSA (IAM Role for Service Account)
        readinessProbe:
          httpGet:
            path: /api/agent-auth/healthz
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          failureThreshold: 3
        livenessProbe:
          httpGet:
            path: /api/agent-auth/healthz
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        resources:
          requests: { cpu: "200m", memory: "512Mi" }
          limits:   { cpu: "2000m", memory: "2Gi" }
      volumes:
      - name: readiness-marker
        emptyDir: {}
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agent-auth-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agent-auth-app
  minReplicas: 3
  maxReplicas: 50
  metrics:
  - type: Resource
    resource:
      name: cpu
      target: { type: Utilization, averageUtilization: 60 }
  - type: Pods
    pods:
      metric: { name: agent_auth_validation_latency_p99_seconds }
      target: { type: AverageValue, averageValue: "0.05" }
```

### 13.1.2 Background worker deployment

Separate deployment for jobs that should not run on every app pod:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: agent-auth-worker }
spec:
  replicas: 1            # singleton worker (jobs use FOR UPDATE SKIP LOCKED, but reduce contention)
  template:
    spec:
      containers:
      - name: worker
        command: ["node", "dist/worker.js"]
        env: # same secrets as app
```

Worker handles:
- Webhook replay polling (every 5min)
- Idempotency reconciliation (every 60s)
- Audit hash chain verifier (hourly)
- Audit outbox flusher (continuous)
- Redis SET reconciliation (hourly)
- Registration session reaper (every minute)
- Audit log partition manager (daily)

### 13.1.3 Post-promotion job

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: post-promotion-reset }
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: reset
        command: ["/scripts/post-promotion-reset.sh"]
        # Triggered by Postgres failover automation (RDS event → Lambda → kubectl create job)
```

## 13.2 Database setup

### 13.2.1 Primary region

```hcl
# Terraform
resource "aws_rds_cluster" "agent_auth_primary" {
  cluster_identifier      = "agent-auth-primary"
  engine                  = "aurora-postgresql"
  engine_version          = "16.1"
  database_name           = "agent_auth"
  master_username         = "postgres"
  master_password         = data.aws_secretsmanager_secret_version.db_master.secret_string

  backup_retention_period = 30
  preferred_backup_window = "03:00-05:00"

  storage_encrypted   = true
  kms_key_id         = aws_kms_key.db_encryption.arn

  enabled_cloudwatch_logs_exports = ["postgresql"]

  iam_database_authentication_enabled = true

  # Tier B durability requires synchronous standby
  cluster_parameters {
    name = "synchronous_standby_names"
    value = "ANY 1 (replica1, replica2)"
  }
}

resource "aws_rds_cluster_instance" "agent_auth_writer" {
  cluster_identifier = aws_rds_cluster.agent_auth_primary.id
  instance_class     = "db.r6g.xlarge"
  publicly_accessible = false
}

resource "aws_rds_cluster_instance" "agent_auth_replica1" {
  cluster_identifier   = aws_rds_cluster.agent_auth_primary.id
  instance_class       = "db.r6g.xlarge"
  publicly_accessible  = false
  availability_zone    = "us-east-1a"
}

resource "aws_rds_cluster_instance" "agent_auth_replica2" {
  cluster_identifier   = aws_rds_cluster.agent_auth_primary.id
  instance_class       = "db.r6g.xlarge"
  publicly_accessible  = false
  availability_zone    = "us-east-1b"
}
```

### 13.2.2 Multi-region (active-passive)

```hcl
resource "aws_rds_global_cluster" "agent_auth_global" {
  global_cluster_identifier = "agent-auth-global"
  engine                    = "aurora-postgresql"
  engine_version            = "16.1"
}

# Primary in us-east-1
resource "aws_rds_cluster" "primary_us_east_1" {
  cluster_identifier        = "agent-auth-primary-use1"
  global_cluster_identifier = aws_rds_global_cluster.agent_auth_global.id
  # ...
}

# Read replica in us-west-2
resource "aws_rds_cluster" "secondary_us_west_2" {
  cluster_identifier        = "agent-auth-secondary-usw2"
  global_cluster_identifier = aws_rds_global_cluster.agent_auth_global.id
  provider                  = aws.us_west_2
  # ...
}
```

## 13.3 Redis setup

```hcl
resource "aws_elasticache_replication_group" "agent_auth_redis" {
  replication_group_id       = "agent-auth-redis"
  description                = "Cache + GCRA + epoch"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2

  engine                     = "redis"
  engine_version             = "7.2"

  port                       = 6379

  automatic_failover_enabled = true
  multi_az_enabled           = true

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true

  # Eviction policy: noeviction (lib expects keys to persist)
  parameter_group_name = aws_elasticache_parameter_group.agent_auth.name
}

resource "aws_elasticache_parameter_group" "agent_auth" {
  name   = "agent-auth-redis"
  family = "redis7"
  parameter {
    name  = "maxmemory-policy"
    value = "noeviction"
  }
}
```

## 13.4 KMS setup

Three keys, ideally in three separate AWS accounts:

```hcl
# Account 111111111111 (app)
resource "aws_kms_key" "agent_auth_pepper" {
  description             = "agent-auth API key HMAC pepper"
  key_usage              = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"
  enable_key_rotation     = false   # manual rotation via dual-pepper period
}

# Account 222222222222 (audit reader, separate trust domain)
resource "aws_kms_key" "audit_reader_decrypt" {
  description = "audit log reader decryption"
  # ... policy restricts to audit-reader-role only
}

# Account 333333333333 (KMS admin, separate trust domain)
resource "aws_kms_key" "audit_encryption" {
  description = "audit log encryption (write side)"
  # ... policy: app-write only, no decrypt
}
```

## 13.5 S3 Object Lock setup

```hcl
resource "aws_s3_bucket" "audit_worm" {
  bucket = "agent-auth-audit-worm"
  provider = aws.audit_account   # account 222222222222

  # Object Lock requires versioning
  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_worm" {
  bucket = aws_s3_bucket.audit_worm.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"   # cannot be deleted/overwritten by anyone, including root
      years = 7
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_worm" {
  bucket = aws_s3_bucket.audit_worm.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.audit_encryption.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_policy" "audit_worm_deny_delete" {
  bucket = aws_s3_bucket.audit_worm.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Deny"
      Principal = "*"
      Action    = ["s3:DeleteObject*", "s3:PutBucketVersioning"]
      Resource  = [
        "${aws_s3_bucket.audit_worm.arn}/*",
        aws_s3_bucket.audit_worm.arn
      ]
    }]
  })
}
```

## 13.6 Network architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ AWS VPC (us-east-1)                                              │
│                                                                  │
│  ┌────────────────────┐   ┌──────────────────────┐              │
│  │  Public ALB        │   │  WAF                 │              │
│  │  (TLS termination) │   │  (DDoS, rate limit)  │              │
│  └─────────┬──────────┘   └──────────┬───────────┘              │
│            │                          │                          │
│            └──────────┬───────────────┘                          │
│                       ▼                                          │
│  ┌─────────────────────────────────────────────────┐            │
│  │  Private subnet (3 AZs)                          │            │
│  │                                                  │            │
│  │  K8s pods (agent-auth-app + worker)             │            │
│  │       │                                          │            │
│  │       ├── Postgres (RDS, multi-AZ + sync standby)│            │
│  │       ├── Redis (ElastiCache, multi-AZ)         │            │
│  │       ├── KMS (AWS managed, IRSA access)        │            │
│  │       └── S3 (audit WORM, separate account VPC peering or private endpoint) │
│  └─────────────────────────────────────────────────┘            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```


---

# Appendix A — Glossary

| Term | Definition |
|---|---|
| Account | An abstract entity owned by a human user; identified by `agent_accounts.id`. Has 0..N identities and 0..N keys. |
| Identity | A binding between an account and an upstream-verified subject (e.g. GitHub numeric ID). Stored in `agent_identities`. |
| Key | An issued API token (`agk_<id>_<secret>`) authenticated via HMAC-SHA256 with KMS pepper. |
| Tier (key) | `cold` / `warm` / `hot`; determines rate limits and which scopes are usable. |
| Tier (durability) | Tier A = async streaming replication (5-min RPO). Tier B = synchronous_commit=remote_apply (0 RPO). |
| Sealed box | libsodium `crypto_box_seal` anonymous public-key encryption used to deliver issued secrets to agent. |
| GCRA | Generic Cell Rate Algorithm; token-bucket variant used for rate limiting. |
| LSN | PostgreSQL Log Sequence Number; monotonic position in WAL. Used for cross-region barrier. |
| Barrier | Global LSN representing the highest write at which any revocation has been durably committed. |
| Epoch | Monotonic counter incremented on every revocation; used for cache validity checks. |
| Audience | This SaaS's IdP client_id; binds OAuth tokens to this specific SaaS. |
| Confused deputy | Class of bug where an authentication context is used for the wrong principal (e.g. `req.user` populated by agent middleware). |
| Sybil | Attack where one entity creates many fake accounts to amass resources. |
| WORM | Write Once Read Many; immutable storage. We use S3 Object Lock COMPLIANCE mode. |
| Crypto-erasure | Destroying a cryptographic key so encrypted data becomes unreadable; used for GDPR right-to-erasure when data is legally retained. |
| Idempotency-Key | Client-supplied UUID via header; ensures retries don't duplicate Tier B operations. |
| Recovery | Flow for re-issuing a key when previous keys are lost; requires fresh OAuth + optional owner approval. |
| Revalidation | Periodic confirmation that user still authorizes the GitHub App; via forced fresh OAuth. |
| Tier B operation | Any operation that creates an irreversible deny-state (revoke, suspend, close, emergency-rotate). Uses synchronous_commit=remote_apply. |
| Trust domain separation | Distributing critical resources across multiple AWS accounts so single-account compromise doesn't compromise everything. |

---

# Appendix B — Decision Log

Every architectural decision below was made over the 13-round codex audit cycle. References point to the audit round that drove the decision.

## ADR-001: Parallel rail, not replacement

**Decision**: agent-auth mounts as new route prefix; never modifies existing human auth.
**Drivers**: Round-1 codex feedback that "convince SaaS to add agent tier" was a structural dealbreaker.
**Consequence**: SaaS adoption is a 3-line install, not a re-architecture.

## ADR-002: Build agent-native, not fork Better Auth

**Decision**: ~1200 lines TypeScript from scratch, no Better Auth fork.
**Drivers**: Better Auth has 80% human-flow code (passwords, sessions, browser cookies) that agents don't need; fork would carry maintenance burden + dilute narrative.
**Consequence**: Cleaner abstractions, focused threat model, easier to evolve with agent ecosystem.

## ADR-003: HMAC + KMS pepper for API key hashing (not Argon2id)

**Decision**: HMAC-SHA256 with KMS-held pepper.
**Drivers**: Round-9 codex feedback that Argon2id is for low-entropy passwords; API keys are 256-bit random.
**Consequence**: ~1ms verify vs ~30ms; KMS-pepper compromise required to attack DB dump.

## ADR-004: Sealed box for secret delivery

**Decision**: libsodium `crypto_box_seal` with agent-generated ephemeral X25519 keypair.
**Drivers**: Round-7 codex feedback that idempotent retrieval requires recipient-only-decryptable storage.
**Consequence**: Lib operators cannot read past secrets; forward secrecy if internal_secret leaks.

## ADR-005: Tier B with synchronous_commit=remote_apply

**Decision**: Revocations and other deny-state operations use Postgres synchronous replication.
**Drivers**: Round-7+8 codex requirements for production-grade revocation correctness.
**Consequence**: 0 RPO for Tier B; standby unreachable causes 503; client retries with idempotency.

## ADR-006: LSN barrier protocol for multi-region correctness

**Decision**: Validation in secondary regions reads barrier LSN from PRIMARY; checks local replay LSN >= barrier.
**Drivers**: Round-12 codex finding that local replica can have stale barrier value.
**Consequence**: Secondary region validation is correct post-revocation; performance cost is 1 cross-region read in strict mode.

## ADR-007: Idempotency two-phase + observer + manual_required terminal

**Decision**: Reservation in own transaction; operation in Tier B transaction; observer reconciles unknowns; gives up to manual after 5 attempts.
**Drivers**: Round-10+11 codex feedback on durable pre-transaction reservation requirement.
**Consequence**: Self-healing for most infrastructure failures; explicit operator escalation for unrecoverable.

## ADR-008: Webhook HMAC verify before dedup INSERT

**Decision**: Verify HMAC over raw body BEFORE touching DB.
**Drivers**: Round-7 codex finding that dedup-then-verify allows attackers to poison dedup table.
**Consequence**: Invalid traffic cannot fill nonce/dedup storage.

## ADR-009: Forced fresh OAuth revalidation (not stored user tokens)

**Decision**: Default revalidation triggers full OAuth dance (no token storage).
**Drivers**: Round-8 codex feedback that installation token cannot validate user authorization.
**Consequence**: 14-day default cadence (per round-10 UX feedback); no long-lived user credentials in lib storage.

## ADR-010: External WORM audit + 3-account trust domain separation

**Decision**: S3 Object Lock COMPLIANCE in separate AWS account; KMS in another separate account.
**Drivers**: Round-9 codex feedback that single-account compromise should not enable audit tampering.
**Consequence**: Compromise of ANY single AWS account does not break audit trail integrity.

## ADR-011: Crypto-erasure with per-subject KMS keys (or shared-pepper fallback)

**Decision**: Per-subject KMS HMAC keys for pseudonymization; deletion via `kms.scheduleKeyDeletion(30 days)`.
**Drivers**: Round-12 codex feedback that shared pepper doesn't enable per-subject erasure.
**Consequence**: True crypto-erasure path available; shared-pepper fallback honestly labeled "minimization, not erasure".

## ADR-012: Risk score is heuristic, not Sybil defense

**Decision**: Warm tier auto-promotion via behavioral risk score; hot tier requires manual SaaS owner gate.
**Drivers**: Round-9 codex feedback that all heuristic signals are gameable by patient attacker.
**Consequence**: SaaS owner is the policy authority for hot tier; warm tier doesn't unlock expensive ops.

## ADR-013: Stop iterating at A spec / production-ready design

**Decision**: 13 codex audit rounds, converging at A grade. A+ requires operational evidence (deploys, audits) that cannot be achieved in spec form.
**Drivers**: Round-13 codex literal verdict: "Stop iterating. Yes."
**Consequence**: Spec is implementation-ready; further value comes from implementation tests + real-world operational data.

## ADR-014: Resolve tierBCommit vs tierBIdempotent error contract

**Decision**: `tierBCommit` (§4.3) is the only place that converts raw `TierBTimeoutError` / pg `XX098` to `ServiceUnavailableError(durability_unconfirmed | durability_unavailable)`. `tierBIdempotent` (§5.1.1) catches that already-converted error (or, defensively, the raw `TierBTimeoutError` if a caller bypasses `tierBCommit`), persists `state='unknown'` on the idempotency row, and re-throws as `ServiceUnavailableError(idempotency_unknown_outcome)` so the caller knows the idempotency observer (§5.1.2) will reconcile.

**Drivers**: SPEC §4.3 and §5.1.1 each specify a `catch (err) { if (err instanceof TierBTimeoutError)` clause but the natural composition (idempotency wraps tierBCommit) means only one of them can see the raw error. Implementation requires picking a single owner.
**Consequence**: Idempotency-aware Tier B routes (§2.7.2 emergency rotate, §2.8 revoke, RB-2 cascade suspend, etc.) get a deterministic 503 with the idempotency-related code; non-idempotent Tier B paths surface the durability-related code from §4.3. Both paths still result in `state='unknown'` rows the observer can reconcile.

---

**End of SPEC.md**

For audit history and design rationale, see `audit/round-{1..13}-*.md`.
For runbooks: `docs/runbooks/RB-{1..9}-*.md`.
For GDPR templates: `docs/gdpr/{lia,dpia,ropa}.md`.
