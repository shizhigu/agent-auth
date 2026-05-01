# Error codes

Vouch returns errors in a stable JSON shape (SPEC §10.3):

```json
{
  "error": {
    "code": "<machine-readable code>",
    "message": "<human description>",
    "request_id": "<uuid>",
    "documentation_url": "https://github.com/.../errors#<code>",
    "details": { /* optional, code-specific */ }
  }
}
```

The `code` is the only field your client should switch on; `message` and `details` are human/diagnostic.

## Auth + key validation

| HTTP | Code | When |
|---|---|---|
| 401 | `invalid_key` | Bearer is missing, malformed, expired, revoked, or doesn't match the tenant. The catch-all for "this Authorization header isn't going to work." |
| 401 | `key_expired` | Key passed signature check but `expires_at` is in the past. |
| 401 | `rotation_grace_expired` | Key was rotated; grace window for the old key has elapsed. |
| 401 | `account_suspended` | The agent's account is suspended. |
| 403 | `insufficient_scope` | Bearer is valid but lacks the required scope (e.g. `self:revoke`). |
| 403 | `tenant_mismatch` | Bearer is valid but the requested tenant doesn't match. |
| 503 | `idp_circuit_open` | The configured identity provider is failing too often; lib's circuit breaker is open (RT-43). |

## Registration / recovery

| HTTP | Code | When |
|---|---|---|
| 400 | `invalid_request` | Request body / params didn't parse. Generic. |
| 400 | `invalid_intent` | `intent` is not one of `register`/`recover`/`add_key`/`revalidate`. |
| 400 | `invalid_provider` | `provider` doesn't match a configured `IdentityProvider`. |
| 400 | `invalid_label` | `label` is empty or > 64 chars. |
| 400 | `invalid_client_pubkey` | `client_pubkey` isn't 32 base64url-encoded bytes. |
| 400 | `missing_account_id_for_intent` | `intent=recover` or `add_key` requires `account_id`. |
| 410 | `session_expired` | Poll token's session is past TTL. |
| 410 | `invalid_kind` | Poll token's kind doesn't match the endpoint (RT-21). |
| 410 | `invalid_poll_token` | Poll token doesn't parse or doesn't exist. |
| 410 | `audience_mismatch` | Identity provider returned an audience that doesn't match the session's. |
| 410 | `identity_account_mismatch` | Recovery target_account_id doesn't match the identity's existing account (RT-31). |
| 410 | `owner_denied_recovery` | The owner explicitly denied the recovery webhook. |

## Rate limiting

| HTTP | Code | When |
|---|---|---|
| 429 | `too_many_requests` | GCRA bucket exceeded for one of the configured dimensions (per-IP, per-account, per-tenant). Includes `Retry-After` header. |
| 429 | `idempotency_in_flight` | A previous request with the same `Idempotency-Key` is still pending (RT-27). Retry after the suggested backoff. |

## Idempotency

| HTTP | Code | When |
|---|---|---|
| 409 | `idempotency_payload_mismatch` | Same `Idempotency-Key` reused with a different request body (SPEC §5.1.3, RT-27). |
| 503 | `idempotency_unknown_outcome` | Tier B mutation timed out without confirming durability. The reconciler will resolve eventually; client should retry the same request to learn the verdict. |

## Webhooks

| HTTP | Code | When |
|---|---|---|
| 400 | `webhook_verify_failed` | HMAC signature didn't verify against the current or previous webhook secret. |
| 404 | `unknown_provider` | URL provider doesn't match a configured `IdentityProvider`. Anti-enumeration: never disclose unknown vs unsupported. |

## Service availability

| HTTP | Code | When |
|---|---|---|
| 503 | `service_unavailable` | Generic — pg / Redis / KMS unreachable, etc. |
| 503 | `audit_unavailable` | The Tier B audit-WORM write failed and the lib refuses to emit a key without an audit trail (RT-28). |
| 503 | `durability_unavailable` | Tier B commit didn't reach a quorum / replica. Client should retry. |
| 503 | `kms_unavailable` | Pepper fetch from KMS failed (RT-22). |

## Recovery / two-person rule

| HTTP | Code | When |
|---|---|---|
| 401 | `co_signer_required` | Admin runbook needs a second signer (SPEC §8.1, RT-10). |
| 401 | `co_signer_canonical_mismatch` | Co-signer's signature is for a different envelope (RT-10 envelope substitution). |
| 401 | `recovery_signature_invalid` | Owner-approval HMAC didn't verify (RT-19). |

## Internal

| HTTP | Code | When |
|---|---|---|
| 500 | `internal_error` | Unexpected. Logged. The `request_id` in the response correlates with server logs. |

## Adding `documentation_url`

The lib doesn't write a `documentation_url` field by default. If you pass `docs_url_base` to `expressMiddleware` (or `honoMiddleware`), every error gets `documentation_url = <docs_url_base>#<code>`:

```ts
app.use('/api/agent/v1', auth.express.middleware({
  docs_url_base: 'https://my-saas.com/docs/agent-auth/errors',
}));
```
