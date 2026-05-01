/**
 * {{name}} — an AI agent that authenticates against a Vouch-protected SaaS.
 *
 * The flow:
 *   1. `register()` generates a Curve25519 keypair, calls /agent-auth/begin-
 *      registration, surfaces the IdP authorization URL, polls for completion,
 *      and decrypts the sealed-box payload to get a bearer key.
 *   2. `vouch.fetch()` is `fetch`-compatible with `Authorization: Bearer …`
 *      auto-injected.
 *
 * For persistence, capture `vouch.bearer / .key_id / .account_id` into your
 * keychain after the first run and use `fromBearer({ ... })` on subsequent
 * runs to skip registration.
 */
import { register } from '@vouch/client';

const SAAS = process.env.SAAS_BASE_URL ?? 'http://localhost:8080';

async function main() {
  const vouch = await register({
    saas_url: SAAS,
    provider: 'github_app',
    label: '{{name}}',
    onChallengeUrl: (url) => {
      console.log(`Authorize at: ${url}`);
      console.log('(open in a browser; click "Authorize" on the IdP consent page)');
    },
  });

  console.log(
    `Registered. account_id=${vouch.account_id}, key_id=${vouch.key_id}, scopes=${vouch.scopes.join(', ')}`,
  );

  // Use the bearer to call any protected route.
  const res = await vouch.fetch('/api/agent/v1/whoami');
  console.log(`whoami → HTTP ${res.status}`);
  console.log(await res.json());
}

main().catch((err) => {
  console.error('Agent failed:', err);
  process.exit(1);
});
