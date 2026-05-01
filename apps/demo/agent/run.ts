/**
 * Vouch demo agent — emulates what `@vouch/client` (v0.2) will do for you.
 *
 * Today's agents have to implement this themselves — the goal of v0.2's
 * client SDK is to reduce this entire script to ~5 lines of agent code.
 *
 * Lifecycle:
 *   1. Generate a Curve25519 keypair (the agent's identity for sealed-box)
 *   2. POST /agent-auth/begin-registration  → { challenge_url, poll_token }
 *   3. GET challenge_url (in this demo, that's the auto-approve route — in
 *      production it's "open in browser, human clicks Authorize")
 *   4. Poll /agent-auth/registration-status until status='completed'
 *   5. Sealed-box decrypt the encrypted_payload → bearer key (`pak_...`)
 *   6. Call protected API with `Authorization: Bearer pak_...`
 *
 * Run: `npm run agent` (after `npm run saas` in another terminal).
 */
import sodium from 'libsodium-wrappers';

const SAAS = process.env.SAAS_BASE_URL ?? 'http://localhost:3000';

async function main() {
  await sodium.ready;

  // ---------------------------------------------------------------------
  // Step 1. Generate ephemeral keypair. The pubkey gates the sealed-box
  // delivery — only THIS agent process can decrypt the bearer key.
  // ---------------------------------------------------------------------
  const kp = sodium.crypto_box_keypair();
  const pub_b64url = Buffer.from(kp.publicKey).toString('base64url');

  console.log(`[1/6] Generated agent keypair (pubkey=${pub_b64url.slice(0, 12)}...)`);

  // ---------------------------------------------------------------------
  // Step 2. Begin registration.
  // ---------------------------------------------------------------------
  const beginRes = await fetch(`${SAAS}/agent-auth/begin-registration`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      provider: 'demo-stub',
      intent: 'register',
      label: 'demo-agent',
      client_pubkey: pub_b64url,
    }),
  });
  if (!beginRes.ok) throw new Error(`begin-registration failed: ${await beginRes.text()}`);
  const begin = (await beginRes.json()) as { poll_token: string; challenge_url: string };
  console.log(`[2/6] Got poll_token=${begin.poll_token.slice(0, 12)}... + challenge_url`);

  // ---------------------------------------------------------------------
  // Step 3. Visit the challenge URL. In the demo this auto-approves; in
  // production it opens a browser tab where the human clicks Authorize.
  // ---------------------------------------------------------------------
  const approveRes = await fetch(begin.challenge_url, { redirect: 'follow' });
  if (!approveRes.ok) throw new Error(`approval failed: ${approveRes.status}`);
  console.log(`[3/6] Auto-approved (in production: human clicks "Authorize" on IdP)`);

  // ---------------------------------------------------------------------
  // Step 4. Poll registration-status until completed.
  // ---------------------------------------------------------------------
  let payload: string | null = null;
  let account_id = '';
  for (let attempt = 0; attempt < 30; attempt++) {
    const url = `${SAAS}/agent-auth/registration-status?poll_token=${encodeURIComponent(begin.poll_token)}`;
    const sRes = await fetch(url);
    const status = (await sRes.json()) as
      | { status: 'pending' }
      | { status: 'completed'; account_id: string; encrypted_payload: string | null; is_first_key: boolean }
      | { status: 'failed'; code: string; message: string };
    if (status.status === 'completed') {
      payload = status.encrypted_payload;
      account_id = status.account_id;
      console.log(`[4/6] Registration completed (account_id=${account_id}, first_key=${status.is_first_key})`);
      break;
    }
    if (status.status === 'failed') {
      throw new Error(`registration failed: ${status.code} — ${status.message}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!payload) throw new Error('registration timed out');

  // ---------------------------------------------------------------------
  // Step 5. Decrypt the sealed box → bearer key.
  // ---------------------------------------------------------------------
  const cipherBytes = Buffer.from(payload, 'base64url');
  const cleartext = sodium.crypto_box_seal_open(cipherBytes, kp.publicKey, kp.privateKey);
  // Sealed payload schema is fixed by SPEC §2.6 — the field is named
  // `key` (the bearer token starts with `pak_`); related fields:
  // key_id, account_id, scopes, tier, is_first_key, issued_at.
  const decoded = JSON.parse(Buffer.from(cleartext).toString('utf8')) as {
    key: string;
    key_id: string;
    account_id: string;
    scopes: string[];
    tier: string;
    is_first_key: boolean;
    issued_at: string;
  };
  console.log(`[5/6] Decrypted bearer key (key=${decoded.key.slice(0, 12)}..., key_id=${decoded.key_id}, tier=${decoded.tier})`);

  // ---------------------------------------------------------------------
  // Step 6. Use the bearer to hit a protected route.
  // ---------------------------------------------------------------------
  const apiRes = await fetch(`${SAAS}/api/agent/v1/whoami`, {
    headers: { authorization: `Bearer ${decoded.key}` },
  });
  if (!apiRes.ok) throw new Error(`whoami failed: ${apiRes.status} ${await apiRes.text()}`);
  const me = await apiRes.json();
  console.log(`[6/6] Hit /api/agent/v1/whoami:`, me);

  console.log('\nDone. Agent successfully registered and called a protected API.');
  console.log(`   account_id : ${account_id}`);
  console.log(`   key_id     : ${decoded.key_id}`);
  console.log(`   pubkey     : ${pub_b64url.slice(0, 16)}...`);
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exit(1);
});
