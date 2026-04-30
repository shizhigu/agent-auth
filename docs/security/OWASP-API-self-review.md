# OWASP API Security Top 10 (2023) — Self-Review

A lib-side accounting against OWASP API 2023. Each row maps the
OWASP risk to the agent-auth surface and the controls that mitigate
it. The "applicability" column distinguishes lib-owned controls
from SaaS responsibilities — agent-auth is one rail of the SaaS's
API surface, so several of the OWASP risks live on the SaaS side
of the boundary.

Reference: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

---

## API1:2023 — Broken Object Level Authorization (BOLA)

| Surface | Mitigation | Status |
|---|---|---|
| `/keys` (`GET /api/agent-auth/keys`) | Cross-account guard: query is keyed on `caller.account_id`; even with `admin:keys` scope a caller cannot enumerate keys outside their account. | ✓ |
| `/revoke` | Same — `row.account_id !== deps.caller.account_id` returns 404 (anti-enumeration). | ✓ |
| `/rotate-key` | Caller's `key_id` derived from `req.agent.key_id` (set by the validate-key middleware), not from the body. The handler asserts `old.account_id === caller.account_id`. | ✓ |
| Admin runbooks (rb-revoke-key, rb-suspend-account) | JIT RBAC + WebAuthn + (for high-impact ops) two-person rule. Admin role is gated behind `agent_auth_admin` Postgres role + JIT grant TTL ≤ 4h. | ✓ |

Lib responsibility: ✓. SaaS-side BOLA on the wider product API
remains the SaaS's responsibility.

## API2:2023 — Broken Authentication

| Surface | Mitigation | Status |
|---|---|---|
| Bearer token format | `agk_<8>.<43>` regex; rejected at parse with 401 invalid_key. | ✓ |
| HMAC + KMS pepper (ADR-003) | No password-equivalent key derivation in app code; pepper held in KMS, never in process memory beyond the request. | ✓ |
| Pepper rotation | Dual-window (current + accepted_legacy). validateKey iterates all accepted versions in constant time; legacy versions retired ≥ 7d after rotation. | ✓ |
| Constant-time HMAC compare | `constantTimeEqualBuffers` (Node `timingSafeEqual` under the hood). Iterates ALL accepted versions even after match to keep timing roughly stable. | ✓ |
| Identity revocation cascade | Webhook + admin runbooks revoke identity → keys cascade-revoked in same tx. RT-26 epoch bump invalidates caches. | ✓ |
| Session fixation (RT-21) | poll_token has cryptographic prefix bound to kind via Postgres CHECK; cross-kind tokens (e.g., recovery token at registration) rejected with 410 invalid_kind. | ✓ |

## API3:2023 — Broken Object Property Level Authorization

| Surface | Mitigation | Status |
|---|---|---|
| AgentContext shape | `req.agent` is frozen (`Object.freeze`) and exposes ONLY the fields a SaaS handler is allowed to read: account_id, key_id, identity, scopes, tier. No raw HMAC, no key_pepper_version, no key_hash. | ✓ |
| Audit meta scrubber | All `meta` JSONB passes through `defaultScrubber` before INSERT — high-entropy strings, known secret prefixes, and structural keys (token/secret/password/cookie/credential/private/key$) get redacted. | ✓ |
| `/keys` projection | Returns key_id, prefix (8-char display only), label, scopes, tier, rotation_state, timestamps. No key_hash, no pepper_version, no internal fields. | ✓ |

## API4:2023 — Unrestricted Resource Consumption

| Surface | Mitigation | Status |
|---|---|---|
| Multi-dim GCRA rate limiting | Per-key, per-account, per-route, per-IP; first reject short-circuits. Atomic per-key via Lua. | ✓ |
| Audit meta cap | scrubber's `max_serialized_size_kb` (default 4 KB) replaces oversize objects with a `truncated` marker. | ✓ |
| Webhook payload | `raw_body` Buffer; SaaS framework caps body size before reaching the handler. Lib doesn't store payloads beyond `payload_hash` + 1 KB `payload_snippet`. | ✓ |
| Outbox flusher backlog | Stuck-row guard (attempts ≥ max_attempts) prevents unbounded retry loops. Reaper drains successful flushes. | ✓ |
| Property-test invariant | `GCRA: total accepts in window ≤ burst capacity` covered by fast-check property test. | ✓ |

## API5:2023 — Broken Function Level Authorization

| Surface | Mitigation | Status |
|---|---|---|
| Scope check on `/rotate-key` | `caller.has_scope('self:rotate')` required; insufficient → 403. | ✓ |
| Scope check on `/revoke` | `self:revoke` for own key OR `admin:keys` for any key on the same account; insufficient → 403. | ✓ |
| Scope check on `/keys` | `admin:keys` required. | ✓ |
| Admin CLI dispatcher | Per-command JIT grant + WebAuthn assertion + two-person for destructive ops (close-account, flush-cache, migrate-rollback, force-revoke-all, reset-barrier). | ✓ |

## API6:2023 — Unrestricted Access to Sensitive Business Flows

Lib boundary: agent-auth handles authentication/authorization, NOT
business-flow rate limiting. SaaS apps own protection of high-risk
flows (account-creation throttle, password-reset cooldown, etc.). Lib
contributes:

| Control | Status |
|---|---|
| `too_many_registrations` (per-IP burst limit at `/begin-registration`) | ✓ |
| Registration session TTL (5 min default; 24h when owner-approval configured) | ✓ |
| Recovery webhook owner-approval gate (§2.9) | ✓ |
| Two-person rule on destructive admin ops | ✓ |

## API7:2023 — Server Side Request Forgery (SSRF)

The lib makes outbound HTTP calls in two places:

| Call | Mitigation | Status |
|---|---|---|
| GitHub OAuth `/login/oauth/access_token` + `/user` (browser-flow) | Host pinned to `cfg.github_host` / `cfg.github_api_host` (config-supplied, not user input). | ✓ |
| Owner-approval webhook (`emitOwnerApprovalRequest`) | URL is `cfg.approval_webhook_url` (config-supplied). HMAC-signed canonical headers prevent forgery of the call. | ✓ |
| Webhook replay polling | `cfg.github_api_host` again — config-pinned. | ✓ |

No user-controlled URLs reach `fetch()`.

## API8:2023 — Security Misconfiguration

| Surface | Mitigation | Status |
|---|---|---|
| Strict-mode TypeScript | `exactOptionalPropertyTypes`, `noImplicitOverride`, `noImplicitReturns`. No `any` in security paths. | ✓ |
| Postgres role separation (§3.16) | `agent_auth_app` (NOLOGIN, no UPDATE/DELETE on audit log), `agent_auth_admin` (admin tools only), `agent_auth_readonly` (column-restricted on audit), `agent_auth_migrator` (DDL only). | ✓ |
| Migration idempotency | All up-migrations use `IF NOT EXISTS` / `CREATE OR REPLACE`; down-migrations use `IF EXISTS` guards. Forward+backward+forward integration test verifies the round-trip. | ✓ |
| Internal secret length check | `resolveConfig` rejects internal_secret ≠ 32 bytes at startup. | ✓ |
| PostgresAdapter role whitelist | Runtime check rejects role values outside the AppRole union (defense in depth against SQL injection via `as any`). | ✓ |
| Append-only audit log | `agent_auth_app` has INSERT+SELECT only on `agent_audit_log`; no UPDATE/DELETE grant. Hash-chain trigger enforces canonical bytes. | ✓ |

## API9:2023 — Improper Inventory Management

| Surface | Mitigation | Status |
|---|---|---|
| Versioned API mount | Lib mounts under `/api/agent-auth/*`; SaaS owns versioning of `/api/agent/v1/*`. | ✓ |
| `.well-known/agent-auth` discovery | Returns endpoints, supported_providers, available_scopes, rate_limit_headers — clients discover capability rather than guess. | ✓ |
| Deprecation headers | Errors include `documentation_url`; SPEC §10.5 documents `Deprecation` + `Sunset` + `Link: rel=deprecation` headers for SaaS use. | ✓ |
| CHANGELOG | Keep a Changelog format; security implications enumerated per release. | ✓ |

## API10:2023 — Unsafe Consumption of APIs

| Surface | Mitigation | Status |
|---|---|---|
| GitHub /user response shape | Validated: `typeof user.id === 'number'`, `typeof user.login === 'string'`. Other fields ignored. | ✓ |
| Webhook payload | HMAC verified BEFORE parse (RT-30); JSON parse failure → 400. Action emission filters by `event_type === 'github_app_authorization'` AND `action === 'revoked'` AND `sender.id !== undefined`. | ✓ |
| Owner-approval inbound | Canonical envelope reconstructed from part fields server-side and HMAC over the reconstruction (not over caller-supplied `canonical`) — RT-10 envelope-substitution defense. | ✓ |
| Sealed-box plaintext | libsodium `crypto_box_seal` with X25519 + XSalsa20-Poly1305; no custom crypto. Recipient pubkey size strict-checked. | ✓ |

---

## Summary

All 10 OWASP API risks are addressed within the lib boundary. The
common thread: where the lib defines the boundary (validate-key,
admin CLI, /callback, audit), defenses are explicit and tested
(unit + integration + chaos). Where the SaaS owns the boundary (the
wider product API surface), this lib provides primitives — typed
`req.agent`, scope-required helpers, scrubbed audit / metric labels —
and documents the SaaS responsibility.

The deep audit cycle covered in `IMPLEMENTATION_STATUS.md` (post-v0.1
sweep) iterated against this same risk matrix and produced ~30 fixes
spanning A1, A2, A3, A4, A5, A8, and A10 categories.
