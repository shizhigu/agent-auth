# Lifecycle routes reference

The 12 routes Vouch mounts when you call `auth.express.mount(app)` (or `app.route('/agent-auth', honoRoutes(auth))`).

| Method | Path | Auth | What it does |
|---|---|---|---|
| `POST` | `/begin-registration` | none | Agent begins registration. Returns `{ poll_token, challenge_url, poll_interval_seconds, expires_at }`. |
| `GET` | `/callback` | none | IdP OAuth callback. Verifies PKCE + state, exchanges code, mints key, sealed-box encrypts. |
| `GET` | `/registration-status` | none | Agent polls. Returns `{ status: 'pending' | 'completed' | 'failed', encrypted_payload?: ... }`. |
| `POST` | `/recover-account` | none | Cross-device recovery flow start (per SPEC §2.9). Same shape as begin-registration. |
| `POST` | `/recover-account-confirm/:token` | HMAC | Owner approves/denies recovery. Body: `{ decision: 'approved' \| 'denied', reason? }`. Verified against the rotating webhook secret. |
| `GET` | `/recover-account-status` | none | Agent polls recovery status. |
| `POST` | `/rotate-key` | Bearer | Self-rotate (requires `self:rotate` scope). |
| `POST` | `/revoke` | Bearer | Self-revoke (requires `self:revoke`) or admin revoke (requires `admin:keys`). |
| `GET` | `/list-keys` | Bearer | List the caller's keys (admin: also see other accounts in the same tenant). |
| `POST` | `/webhooks/:provider` | HMAC | IdP webhook (org deauth, SAML deprovision). Raw-body verified — body parsing skipped. |
| `GET` | `/healthz` | none | Health check. 200 = healthy, 503 = unhealthy. |
| `GET` | `/well-known` | none | Capability discovery — what providers, scopes, rate-limit headers, barrier mode. |

## Begin-registration shape

```http
POST /agent-auth/begin-registration
Content-Type: application/json

{
  "provider": "github_app",
  "intent": "register",
  "client_pubkey": "<base64url 32-byte pubkey>",
  "label": "claude-code-laptop",
  "account_id": "<UUID>"     // required for intent=recover or add_key
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "poll_token": "pak_…",
  "challenge_url": "https://github.com/login/oauth/authorize?...",
  "poll_interval_seconds": 2,
  "expires_at": "2026-04-30T20:30:00.000Z"
}
```

## Callback shape

The callback URL is what your IdP redirects to after `Authorize`. The lib doesn't render HTML — it returns JSON:

```http
GET /agent-auth/callback?state=<nonce>&code=<oauth_code>&provider=github_app
```

Success → `200 { status: 'success', account_id, is_first_key }`. Failure → `200 { status: 'failed', reason }`.

::: tip Render an HTML page instead?
Wrap the route after `auth.express.mount(app)`:

```ts
auth.express.mount(app);

app.get('/agent-auth/callback', (req, res, next) => {
  // Vouch already handled it; intercept the response to render HTML.
  // … or just let it pass through and have the agent render via the poll response.
});
```
:::

## Registration-status shape

```http
GET /agent-auth/registration-status?poll_token=pak_…
```

Returns one of:

```json
{ "status": "pending" }
```

```json
{
  "status": "completed",
  "account_id": "<UUID>",
  "encrypted_payload": "<base64url sealed box>",
  "is_first_key": true
}
```

```json
{
  "status": "failed",
  "code": "audience_mismatch",
  "message": "identity audience does not match"
}
```

## Sealed payload contents

After sealed-box decrypt, the payload is a JSON object:

```json
{
  "key": "pak_<37 bytes base64url>",
  "key_id": "agk_<short>",
  "account_id": "<UUID>",
  "scopes": ["read", "self:rotate"],
  "tier": "cold",
  "is_first_key": true,
  "issued_at": "2026-04-30T20:30:01.123Z"
}
```

The `key` is the bearer the agent presents on every subsequent request.

## Errors

All routes return errors in the SPEC §10.3 shape:

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

See [error codes →](/reference/errors)
