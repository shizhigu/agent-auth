/**
 * Unit tests for @vouch/client.
 *
 * Covers the SDK's lifecycle without standing up a real SaaS: a mock
 * `fetcher` records / replays the HTTP traffic and a real libsodium
 * sealed-box round-trip validates the decrypt path.
 */
import { describe, it, expect } from 'vitest';
import sodium from 'libsodium-wrappers';
import { register, beginRegistration, fromBearer } from '../src/index.js';

type MockRoute = (input: string | URL, init?: RequestInit) => Response | undefined;

function makeMockFetcher(routes: MockRoute[]): typeof fetch {
  const f: typeof fetch = async (input, init) => {
    // Narrow to what our routes expect — Request inputs aren't used in tests.
    const i =
      typeof input === 'string' || input instanceof URL
        ? (input as string | URL)
        : (input.url as string);
    for (const r of routes) {
      const out = r(i, init);
      if (out) return out;
    }
    throw new Error(`no mock matched: ${String(i)}`);
  };
  return f;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('@vouch/client — register()', () => {
  it('drives the full lifecycle and returns a session that can fetch', async () => {
    await sodium.ready;

    let agentPubKey: Uint8Array | null = null;
    let pollCount = 0;

    const fakeBearerPayload = (pubkey: Uint8Array) => {
      const payload = {
        key: 'pak_demobearer123',
        key_id: 'agk_xyz',
        account_id: 'acc-1',
        scopes: ['read'],
        tier: 'cold',
        is_first_key: true,
        issued_at: new Date().toISOString(),
      };
      const cleartext = Buffer.from(JSON.stringify(payload), 'utf8');
      const cipher = sodium.crypto_box_seal(cleartext, pubkey);
      return Buffer.from(cipher).toString('base64url');
    };

    const fetcher = makeMockFetcher([
      // begin-registration
      (input, init) => {
        if (typeof input === 'string' && input.endsWith('/agent-auth/begin-registration')) {
          const body = JSON.parse(String(init?.body ?? '{}'));
          agentPubKey = Buffer.from(body.client_pubkey, 'base64url');
          return jsonResponse(200, {
            poll_token: 'pak_polltoken123',
            challenge_url: 'https://idp.example/authorize?state=...',
            poll_interval_seconds: 0,
            expires_at: new Date(Date.now() + 60_000).toISOString(),
          });
        }
        return undefined;
      },
      // registration-status — pending twice, then completed.
      (input) => {
        if (typeof input === 'string' && input.includes('/registration-status')) {
          pollCount++;
          if (pollCount < 2) return jsonResponse(200, { status: 'pending' });
          if (!agentPubKey) throw new Error('expected pubkey to be set');
          return jsonResponse(200, {
            status: 'completed',
            account_id: 'acc-1',
            encrypted_payload: fakeBearerPayload(agentPubKey),
            is_first_key: true,
          });
        }
        return undefined;
      },
      // The protected API endpoint
      (input, init) => {
        if (typeof input === 'string' && input.endsWith('/api/agent/v1/whoami')) {
          const headers = new Headers(init?.headers);
          const auth = headers.get('authorization');
          if (auth !== 'Bearer pak_demobearer123') {
            return jsonResponse(401, { error: { code: 'invalid_key' } });
          }
          return jsonResponse(200, { account_id: 'acc-1', scopes: ['read'] });
        }
        return undefined;
      },
    ]);

    let challengeSeen = '';
    const session = await register({
      saas_url: 'http://saas.example',
      provider: 'github_app',
      fetcher,
      poll_interval_ms: 1,
      poll_timeout_ms: 5_000,
      onChallengeUrl: (url) => {
        challengeSeen = url;
      },
    });

    expect(challengeSeen).toBe('https://idp.example/authorize?state=...');
    expect(session.bearer).toBe('pak_demobearer123');
    expect(session.account_id).toBe('acc-1');
    expect(session.is_first_key).toBe(true);
    expect(session.scopes).toEqual(['read']);

    const r = await session.fetch('/api/agent/v1/whoami');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { account_id: string; scopes: string[] };
    expect(body.account_id).toBe('acc-1');
  });

  it('throws when the SaaS reports failed registration', async () => {
    await sodium.ready;
    const fetcher = makeMockFetcher([
      (input) => {
        if (typeof input === 'string' && input.endsWith('/begin-registration')) {
          return jsonResponse(200, {
            poll_token: 'pak_x',
            challenge_url: 'https://idp/x',
            poll_interval_seconds: 0,
            expires_at: new Date(Date.now() + 60_000).toISOString(),
          });
        }
        return undefined;
      },
      (input) =>
        typeof input === 'string' && input.includes('/registration-status')
          ? jsonResponse(200, {
              status: 'failed',
              code: 'audience_mismatch',
              message: 'identity audience does not match',
            })
          : undefined,
    ]);
    await expect(
      register({
        saas_url: 'http://saas.example',
        provider: 'github_app',
        fetcher,
        poll_interval_ms: 1,
      }),
    ).rejects.toThrow(/audience_mismatch/);
  });

  it('throws on poll timeout', async () => {
    await sodium.ready;
    const fetcher = makeMockFetcher([
      (input) =>
        typeof input === 'string' && input.endsWith('/begin-registration')
          ? jsonResponse(200, {
              poll_token: 'pak_x',
              challenge_url: 'https://idp/x',
              poll_interval_seconds: 0,
              expires_at: new Date(Date.now() + 60_000).toISOString(),
            })
          : typeof input === 'string' && input.includes('/registration-status')
            ? jsonResponse(200, { status: 'pending' })
            : undefined,
    ]);
    await expect(
      register({
        saas_url: 'http://saas.example',
        provider: 'github_app',
        fetcher,
        poll_interval_ms: 5,
        poll_timeout_ms: 50,
      }),
    ).rejects.toThrow(/timed out/);
  });
});

describe('@vouch/client — beginRegistration() staged use', () => {
  it('returns the challenge URL synchronously and lets the caller wait separately', async () => {
    await sodium.ready;
    let pubkey: Uint8Array | null = null;
    const fetcher = makeMockFetcher([
      (input, init) => {
        if (typeof input === 'string' && input.endsWith('/begin-registration')) {
          pubkey = Buffer.from(
            JSON.parse(String(init?.body ?? '{}')).client_pubkey,
            'base64url',
          );
          return jsonResponse(200, {
            poll_token: 'pak_y',
            challenge_url: 'https://idp/y',
            poll_interval_seconds: 0,
            expires_at: new Date(Date.now() + 60_000).toISOString(),
          });
        }
        return undefined;
      },
      (input) => {
        if (typeof input === 'string' && input.includes('/registration-status')) {
          if (!pubkey) throw new Error('expected pubkey set');
          const cleartext = Buffer.from(
            JSON.stringify({
              key: 'pak_staged',
              key_id: 'k',
              account_id: 'a',
              scopes: [],
              tier: 'cold',
              is_first_key: true,
              issued_at: new Date().toISOString(),
            }),
            'utf8',
          );
          const cipher = sodium.crypto_box_seal(cleartext, pubkey);
          return jsonResponse(200, {
            status: 'completed',
            account_id: 'a',
            encrypted_payload: Buffer.from(cipher).toString('base64url'),
            is_first_key: true,
          });
        }
        return undefined;
      },
    ]);
    const flow = await beginRegistration({
      saas_url: 'http://saas',
      provider: 'github_app',
      fetcher,
      poll_interval_ms: 1,
    });
    expect(flow.challenge_url).toBe('https://idp/y');
    const session = await flow.waitForCompletion({ intervalMs: 1, timeoutMs: 5_000 });
    expect(session.bearer).toBe('pak_staged');
  });
});

describe('@vouch/client — fromBearer() rehydration', () => {
  it('builds a session that injects Bearer into fetch', async () => {
    const fetcher = makeMockFetcher([
      (_input, init) => {
        const auth = new Headers(init?.headers).get('authorization');
        return jsonResponse(200, { auth });
      },
    ]);
    const session = fromBearer({
      saas_url: 'http://saas',
      bearer: 'pak_persisted',
      key_id: 'k',
      account_id: 'a',
      fetcher,
    });
    const r = await session.fetch('/api/x');
    const body = (await r.json()) as { auth: string };
    expect(body.auth).toBe('Bearer pak_persisted');
  });

  it('does not overwrite a caller-supplied authorization header', async () => {
    const fetcher = makeMockFetcher([
      (_input, init) => {
        const auth = new Headers(init?.headers).get('authorization');
        return jsonResponse(200, { auth });
      },
    ]);
    const session = fromBearer({
      saas_url: 'http://saas',
      bearer: 'pak_default',
      key_id: 'k',
      account_id: 'a',
      fetcher,
    });
    const r = await session.fetch('/api/x', {
      headers: { authorization: 'Bearer custom' },
    });
    const body = (await r.json()) as { auth: string };
    expect(body.auth).toBe('Bearer custom');
  });
});
