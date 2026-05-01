# Identity providers

Vouch ships three providers out of the box, plus an escape hatch for anything else.

## Pick one (or more — they're additive)

```ts
import { vouch } from '@vouch/server';

const auth = await vouch({
  // ... database / redis / kms / internal_secret ...
  identity: {
    github: { /* GitHubAppProviderConfig */ },
    google: { /* GoogleProviderConfig */ },
    oidc:   { /* OidcProviderConfig (generic) */ },
    custom: [/* IdentityProvider[] */],
  },
});
```

The factory builds providers in declaration order; agents pick which one via `request.body.provider` (e.g. `'github_app' | 'google' | 'okta'`).

## GitHub

```ts
identity: {
  github: {
    client_id: process.env.GH_CLIENT_ID!,
    client_secret: process.env.GH_CLIENT_SECRET!,
    webhook_secret: process.env.GH_WEBHOOK_SECRET!,
    app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,  // .pem contents
    // optional:
    scopes: ['read:user'],            // default
    default_assurance: 'medium',      // default
  },
}
```

**Provider name in API:** `github_app`.

**What it gives you:**
- Browser flow (PKCE + state)
- Webhook handler (`POST /agent-auth/webhooks/github_app`) for org-deauth / SAML deprovisioning cascades
- Revalidation via App-JWT-authenticated `GET /user/{id}` to confirm the upstream identity still resolves

## Google / Google Workspace

```ts
identity: {
  google: {
    client_id: process.env.GOOGLE_CLIENT_ID!,
    client_secret: process.env.GOOGLE_CLIENT_SECRET!,
    hosted_domain: 'acme.com',  // optional — restrict to one Workspace
  },
}
```

**Provider name in API:** `google`.

**What `hosted_domain` does:** Google enforces it server-side via the `hd` authorize-URL param and returns `hd` in the userinfo response. The SaaS should additionally check `attestation.raw_metadata.hd` matches your expected domain (defense in depth — a misconfigured client app could otherwise allow consumer Gmail accounts).

**Custom name:** Pass `name: 'workspace'` to use a different stable name for audit + IdentityProvider.name.

## Generic OIDC

For Microsoft Entra, Okta, Auth0, Keycloak, Ory Hydra, ZITADEL, your in-house IdP — anything that ships a discovery doc.

### Auto-discovery

```ts
identity: {
  oidc: {
    name: 'okta',
    issuer_url: 'https://your-tenant.okta.com',
    client_id: process.env.OKTA_CLIENT_ID!,
    client_secret: process.env.OKTA_CLIENT_SECRET!,
  },
}
```

The provider lazily fetches `${issuer_url}/.well-known/openid-configuration` on the first registration. The discovery doc is cached on the instance.

### Manual configuration

For IdPs that don't ship discovery, or for tests:

```ts
identity: {
  oidc: {
    name: 'inhouse',
    client_id: '...',
    client_secret: '...',
    endpoints: {
      authorization_endpoint: 'https://idp.acme.com/oauth/authorize',
      token_endpoint:         'https://idp.acme.com/oauth/token',
      userinfo_endpoint:      'https://idp.acme.com/oauth/userinfo',
    },
  },
}
```

### Multiple OIDC providers

`identity.oidc` is single-shot. To wire multiple OIDC providers (e.g. Okta + Auth0 in one SaaS), construct them via the exported class and pass them to `identity.custom`:

```ts
import { vouch, OidcProvider } from '@vouch/server';

const okta = new OidcProvider({
  name: 'okta',
  issuer_url: 'https://your-tenant.okta.com',
  client_id: '...',
  client_secret: '...',
});

const auth0 = new OidcProvider({
  name: 'auth0',
  issuer_url: 'https://your-tenant.auth0.com',
  client_id: '...',
  client_secret: '...',
});

const auth = await vouch({
  // ...
  identity: { custom: [okta, auth0] },
});
```

## What the OIDC provider does NOT do (yet)

::: warning
The generic OIDC provider trusts the `userinfo` response over HTTPS rather than verifying the `id_token` JWT signature in v0. The access_token round-trip provides equivalent integrity for the standard server-side authorization-code flow, and skipping JWT/JWKS handling avoids ~200 LOC of bundled crypto. SaaSes that need stricter id_token verification (e.g. for client-side native flows) can subclass `OidcProvider` and override `exchangeOrVerify`.
:::

::: warning
`revalidate()` is a no-op in v0 (returns `still_valid: true`). Real revalidation needs a stored refresh_token or admin API key — which the lib doesn't store. Configure `revalidation.cadence_seconds` to a long value (e.g. 7 days) until you wire a custom revalidate path.
:::

## Custom providers

Any class that implements `IdentityProvider` from `agent-auth` works:

```ts
import type { IdentityProvider, AttestationContext, Attestation } from '@vouch/server';

class SamlBridgeProvider implements IdentityProvider {
  readonly name = 'corp-saml';

  async beginRegistration(_ctx: AttestationContext) {
    return { challenge_url: 'https://sso.corp.example/...' };
  }

  async exchangeOrVerify(input, ctx): Promise<Attestation> {
    // Validate the SAML assertion / bridge token / whatever
    // and return an Attestation.
    return {
      issuer: 'corp-saml',
      subject: 'user-12345',
      audience: ctx.audience,
      assurance_level: 'high',
      supports_revalidation: true,
    };
  }

  async revalidate() {
    return { still_valid: true };
  }
}

const auth = await vouch({
  // ...
  identity: { custom: [new SamlBridgeProvider()] },
});
```

The lib enforces invariants the provider doesn't have to:
- Single-use `nonce` (RT-29 OAuth state replay)
- PKCE binding to the session row
- `audience` match between provider Attestation and session
- Identity-account binding (RT-31 cross-tenant recovery)

The provider just has to do the IdP-specific dance.
