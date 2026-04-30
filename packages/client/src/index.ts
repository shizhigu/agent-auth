/**
 * @vouch/client — agent-side SDK for the Vouch identity infrastructure.
 *
 * Wraps the registration flow (PKCE keypair generation, polling, sealed-box
 * decrypt) plus bearer-key handling so an AI agent can authenticate in
 * roughly 5 lines:
 *
 *   import { register } from '@vouch/client';
 *
 *   const vouch = await register({
 *     saas_url: 'https://my-saas.com',
 *     provider: 'github_app',
 *     onChallengeUrl: (url) => console.log('Authorize at:', url),
 *   });
 *
 *   const me = await vouch.fetch('/api/agent/v1/whoami').then(r => r.json());
 *
 * The SDK does NOT speak directly to the IdP — that path stays on the SaaS
 * server (per SPEC §2.2). The agent's job is: send `client_pubkey`, get
 * back the sealed-box payload, decrypt locally, present Bearer.
 */

import sodium from 'libsodium-wrappers';

// ---------------------------------------------------------------------------
// Public API surface
// ---------------------------------------------------------------------------

export type Intent = 'register' | 'recover' | 'add_key';

export interface RegisterOptions {
  /** Base URL of the SaaS (no trailing slash). */
  readonly saas_url: string;
  /** Identity provider name as configured on the SaaS (e.g., "github_app"). */
  readonly provider: string;
  /** Default `register`. Use `recover` for cross-device recovery, `add_key` to mint another key for an existing account. */
  readonly intent?: Intent;
  /** Required for `recover` and `add_key` intents. */
  readonly account_id?: string;
  /** Optional human label attached to the key (shown in admin UIs). */
  readonly label?: string;
  /**
   * Called once with the IdP authorization URL the user needs to visit.
   * In a CLI you might log it; in a desktop app, open in the system
   * browser. The SDK does NOT auto-open — the agent decides.
   */
  readonly onChallengeUrl?: (url: string) => void | Promise<void>;
  /** Override the lifecycle path on the SaaS. Defaults to `/agent-auth`. */
  readonly path_prefix?: string;
  /** Override fetch (test injection). Defaults to global `fetch`. */
  readonly fetcher?: typeof fetch;
  /** Polling cadence override (ms). Defaults to the value the SaaS returns. */
  readonly poll_interval_ms?: number;
  /** How long to wait for the human to authorize. Defaults to 5 minutes. */
  readonly poll_timeout_ms?: number;
}

export interface VouchSession {
  /** The Bearer token. Starts with `pak_` for register, `pad_` for add_key. */
  readonly bearer: string;
  readonly key_id: string;
  readonly account_id: string;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: string;
  readonly is_first_key: boolean;
  readonly issued_at: string;
  /**
   * `fetch`-compatible wrapper that injects the bearer token. Relative URLs
   * are resolved against the configured `saas_url`.
   */
  fetch(input: string | URL, init?: RequestInit): Promise<Response>;
}

/**
 * One-shot registration: drives the full flow start to finish.
 *
 * If you need to surface the challenge URL and poll separately, use
 * `beginRegistration` + the returned flow's `waitForCompletion`.
 */
export async function register(opts: RegisterOptions): Promise<VouchSession> {
  const flow = await beginRegistration(opts);
  if (opts.onChallengeUrl) await opts.onChallengeUrl(flow.challenge_url);
  return flow.waitForCompletion({
    ...(opts.poll_interval_ms !== undefined ? { intervalMs: opts.poll_interval_ms } : {}),
    ...(opts.poll_timeout_ms !== undefined ? { timeoutMs: opts.poll_timeout_ms } : {}),
  });
}

export interface RegistrationFlow {
  /** URL the user must visit to authorize the agent. */
  readonly challenge_url: string;
  /** Opaque token used to poll registration status. */
  readonly poll_token: string;
  /** Server-recommended polling interval (seconds). */
  readonly poll_interval_seconds: number;
  /** Session expiry (ISO timestamp). */
  readonly expires_at: string;
  /**
   * Polls /agent-auth/registration-status until terminal. Returns the live
   * session on success. Throws on failure or timeout.
   */
  waitForCompletion(opts?: {
    intervalMs?: number;
    timeoutMs?: number;
  }): Promise<VouchSession>;
}

/**
 * Begin a registration flow without driving polling. Returns the IdP URL
 * (for the agent to surface to the human) plus a `waitForCompletion` to
 * await success.
 */
export async function beginRegistration(opts: RegisterOptions): Promise<RegistrationFlow> {
  await sodium.ready;

  const fetcher = opts.fetcher ?? fetch;
  const prefix = opts.path_prefix ?? '/agent-auth';
  const saas = trimSlash(opts.saas_url);
  const intent: Intent = opts.intent ?? 'register';

  // 1. Curve25519 keypair — pubkey gates the sealed-box delivery.
  const kp = sodium.crypto_box_keypair();
  const pub_b64url = toBase64Url(Buffer.from(kp.publicKey));

  // 2. POST /agent-auth/begin-registration
  const beginBody: Record<string, unknown> = {
    provider: opts.provider,
    intent,
    client_pubkey: pub_b64url,
  };
  if (opts.label) beginBody['label'] = opts.label;
  if (opts.account_id) beginBody['account_id'] = opts.account_id;
  const beginRes = await fetcher(`${saas}${prefix}/begin-registration`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(beginBody),
  });
  if (!beginRes.ok) {
    throw new Error(`begin-registration failed: ${beginRes.status} ${await beginRes.text()}`);
  }
  const begin = (await beginRes.json()) as {
    poll_token: string;
    challenge_url: string;
    poll_interval_seconds: number;
    expires_at: string;
  };

  return {
    challenge_url: begin.challenge_url,
    poll_token: begin.poll_token,
    poll_interval_seconds: begin.poll_interval_seconds,
    expires_at: begin.expires_at,

    async waitForCompletion(waitOpts) {
      const intervalMs =
        waitOpts?.intervalMs ?? Math.max(500, begin.poll_interval_seconds * 1000);
      const timeoutMs = waitOpts?.timeoutMs ?? 5 * 60_000;
      const deadline = Date.now() + timeoutMs;

      while (Date.now() < deadline) {
        const url = `${saas}${prefix}/registration-status?poll_token=${encodeURIComponent(
          begin.poll_token,
        )}`;
        const sRes = await fetcher(url);
        const status = (await sRes.json()) as
          | { status: 'pending' }
          | {
              status: 'completed';
              account_id: string;
              encrypted_payload: string | null;
              is_first_key: boolean;
            }
          | { status: 'failed'; code: string; message: string };

        if (status.status === 'completed') {
          if (!status.encrypted_payload) {
            // SPEC §2.4: revalidate intent has no payload — caller should
            // re-use the existing bearer. Out of scope for the simple
            // `register()` happy path.
            throw new Error('registration completed without payload (revalidate flow not supported by VouchSession)');
          }
          const cipher = fromBase64Url(status.encrypted_payload);
          let cleartext: Uint8Array;
          try {
            cleartext = sodium.crypto_box_seal_open(cipher, kp.publicKey, kp.privateKey);
          } catch (err) {
            throw new Error('sealed-box decrypt failed (wrong keypair?)', { cause: err });
          }
          const decoded = JSON.parse(Buffer.from(cleartext).toString('utf8')) as {
            key: string;
            key_id: string;
            account_id: string;
            scopes: string[];
            tier: string;
            is_first_key: boolean;
            issued_at: string;
          };
          return makeSession({
            saas,
            fetcher,
            bearer: decoded.key,
            key_id: decoded.key_id,
            account_id: decoded.account_id,
            scopes: decoded.scopes,
            tier: decoded.tier,
            is_first_key: decoded.is_first_key,
            issued_at: decoded.issued_at,
          });
        }
        if (status.status === 'failed') {
          throw new Error(`registration failed: ${status.code} — ${status.message}`);
        }
        await sleep(intervalMs);
      }
      throw new Error(`registration timed out after ${timeoutMs} ms`);
    },
  };
}

/**
 * Build a session object from an already-issued bearer (e.g. one you persisted
 * from a previous run). Doesn't talk to the SaaS; the bearer is validated on
 * its first request.
 */
export function fromBearer(opts: {
  saas_url: string;
  bearer: string;
  key_id: string;
  account_id: string;
  scopes?: ReadonlyArray<string>;
  tier?: string;
  is_first_key?: boolean;
  issued_at?: string;
  fetcher?: typeof fetch;
}): VouchSession {
  return makeSession({
    saas: trimSlash(opts.saas_url),
    fetcher: opts.fetcher ?? fetch,
    bearer: opts.bearer,
    key_id: opts.key_id,
    account_id: opts.account_id,
    scopes: opts.scopes ?? [],
    tier: opts.tier ?? 'cold',
    is_first_key: opts.is_first_key ?? false,
    issued_at: opts.issued_at ?? new Date().toISOString(),
  });
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface SessionInputs {
  readonly saas: string;
  readonly fetcher: typeof fetch;
  readonly bearer: string;
  readonly key_id: string;
  readonly account_id: string;
  readonly scopes: ReadonlyArray<string>;
  readonly tier: string;
  readonly is_first_key: boolean;
  readonly issued_at: string;
}

function makeSession(s: SessionInputs): VouchSession {
  const { fetcher, saas, bearer } = s;
  return {
    bearer: s.bearer,
    key_id: s.key_id,
    account_id: s.account_id,
    scopes: s.scopes,
    tier: s.tier,
    is_first_key: s.is_first_key,
    issued_at: s.issued_at,
    async fetch(input, init) {
      const url = typeof input === 'string' && !/^https?:/.test(input) ? `${saas}${input}` : input;
      const headers = new Headers(init?.headers);
      if (!headers.has('authorization')) headers.set('authorization', `Bearer ${bearer}`);
      return fetcher(url, { ...init, headers });
    },
  };
}

function trimSlash(s: string): string {
  return s.endsWith('/') ? s.slice(0, -1) : s;
}

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64url');
}

function fromBase64Url(s: string): Uint8Array {
  return Buffer.from(s, 'base64url');
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
