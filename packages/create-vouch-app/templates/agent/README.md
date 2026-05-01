# {{name}}

{{description}}

A minimal AI agent that authenticates against a Vouch-protected SaaS using [`@vouch/client`](https://github.com/shizhigu/agent-auth/tree/main/packages/client).

## Quick start

```bash
npm install
cp .env.example .env
# Set SAAS_BASE_URL to point at your Vouch SaaS.

npm run dev
# -> Authorize at: https://github.com/login/oauth/authorize?...
# -> (open in browser, click Authorize)
# -> Registered. account_id=…, key_id=…
# -> whoami → HTTP 200
# -> { account_id: '…', scopes: [ 'read', 'self:rotate' ], … }
```

## What the SDK does for you

`@vouch/client`'s `register()` wraps:

1. Generates an ephemeral Curve25519 keypair (the agent's identity).
2. POSTs to `/agent-auth/begin-registration` with the public key.
3. Surfaces the IdP authorization URL via `onChallengeUrl`.
4. Polls `/agent-auth/registration-status` until completion.
5. Sealed-box decrypts the encrypted payload → bearer key (`pak_…`).

After registration, `vouch.fetch(input, init)` is fetch-compatible with `Authorization: Bearer …` injected automatically.

## Persistence

For long-running agents, store `vouch.bearer / .key_id / .account_id` somewhere safe (the OS keychain is ideal) and rebuild the session on the next run:

```ts
import { fromBearer } from '@vouch/client';

const vouch = fromBearer({
  saas_url: process.env.SAAS_BASE_URL!,
  bearer: storedBearer,
  key_id: storedKeyId,
  account_id: storedAccountId,
});
```

## License

MIT
