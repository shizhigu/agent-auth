/**
 * Unit tests for OidcProvider — uses a mock fetcher so no network
 * roundtrip happens. Covers:
 *
 *   - constructor validation (issuer XOR endpoints, name shape, secret presence)
 *   - beginRegistration builds a correct authorize URL with state + PKCE
 *   - exchangeOrVerify hits token + userinfo endpoints and returns Attestation
 *   - discovery: lazy fetch + result caching
 *   - error mapping (token error, userinfo missing sub)
 */
import { describe, it, expect } from 'vitest';
import { OidcProvider } from '../../src/identity/oidc/provider.js';
import type { AttestationContext } from '../../src/types.js';

function fakeCtx(overrides: Partial<AttestationContext> = {}): AttestationContext {
  return {
    audience: 'aud-1',
    nonce: 'state-xyz',
    poll_token: 'pak_x',
    client_pubkey: new Uint8Array(32),
    ip_hash: Buffer.alloc(32),
    user_agent: 'test',
    redirect_uri: 'https://saas.example/agent-auth/callback',
    pkce_challenge: 'CHALLENGE',
    pkce_challenge_method: 'S256',
    intent: 'register',
    ...overrides,
  };
}

interface MockedFetch {
  fetch: typeof fetch;
  calls: Array<{ url: string; init?: RequestInit }>;
}

function mockFetch(routes: Array<(url: string) => Response | undefined>): MockedFetch {
  const calls: MockedFetch['calls'] = [];
  const f: typeof fetch = async (input, init) => {
    const url =
      typeof input === 'string' || input instanceof URL
        ? String(input)
        : (input as Request).url;
    calls.push({ url, ...(init ? { init } : {}) });
    for (const r of routes) {
      const out = r(url);
      if (out) return out;
    }
    throw new Error(`no mock matched: ${url}`);
  };
  return { fetch: f, calls };
}

function jsonRes(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('OidcProvider — constructor', () => {
  it('rejects when neither issuer_url nor endpoints is set', () => {
    expect(
      () =>
        new OidcProvider({
          name: 'p',
          client_id: 'c',
          client_secret: 's',
        }),
    ).toThrow(/issuer_url or endpoints/);
  });

  it('rejects when both issuer_url and endpoints are set', () => {
    expect(
      () =>
        new OidcProvider({
          name: 'p',
          client_id: 'c',
          client_secret: 's',
          issuer_url: 'https://idp.example',
          endpoints: {
            authorization_endpoint: 'a',
            token_endpoint: 't',
            userinfo_endpoint: 'u',
          },
        }),
    ).toThrow(/ONE of issuer_url or endpoints/);
  });

  it('rejects malformed name', () => {
    expect(
      () =>
        new OidcProvider({
          name: 'bad name with spaces',
          client_id: 'c',
          client_secret: 's',
          issuer_url: 'https://idp.example',
        }),
    ).toThrow(/invalid name/);
  });

  it('rejects missing client_id / client_secret', () => {
    expect(
      () =>
        new OidcProvider({
          name: 'p',
          client_id: '',
          client_secret: 's',
          issuer_url: 'https://idp.example',
        }),
    ).toThrow(/client_id and client_secret/);
  });
});

describe('OidcProvider — beginRegistration', () => {
  it('builds an authorize URL with state, PKCE, and scopes', async () => {
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      endpoints: {
        authorization_endpoint: 'https://idp.example/oauth/authorize',
        token_endpoint: 'https://idp.example/oauth/token',
        userinfo_endpoint: 'https://idp.example/oauth/userinfo',
      },
    });
    const out = await provider.beginRegistration(fakeCtx());
    expect(out.challenge_url).toContain('https://idp.example/oauth/authorize?');
    const url = new URL(out.challenge_url!);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('client_id')).toBe('cid');
    expect(url.searchParams.get('state')).toBe('state-xyz');
    expect(url.searchParams.get('code_challenge')).toBe('CHALLENGE');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('scope')).toBe('openid email profile');
  });

  it('includes extra_authorize_params (e.g. hd for Google Workspace)', async () => {
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      endpoints: {
        authorization_endpoint: 'https://idp.example/oauth/authorize',
        token_endpoint: 'https://idp.example/oauth/token',
        userinfo_endpoint: 'https://idp.example/oauth/userinfo',
      },
      extra_authorize_params: { hd: 'acme.com', prompt: 'consent' },
    });
    const out = await provider.beginRegistration(fakeCtx());
    const url = new URL(out.challenge_url!);
    expect(url.searchParams.get('hd')).toBe('acme.com');
    expect(url.searchParams.get('prompt')).toBe('consent');
  });
});

describe('OidcProvider — exchangeOrVerify', () => {
  it('exchanges code for access_token, fetches userinfo, returns Attestation', async () => {
    const m = mockFetch([
      (url) =>
        url === 'https://idp.example/oauth/token'
          ? jsonRes(200, { access_token: 'at_x', token_type: 'Bearer' })
          : undefined,
      (url) =>
        url === 'https://idp.example/oauth/userinfo'
          ? jsonRes(200, { sub: 'user-42', email: 'alice@acme.com', name: 'Alice', hd: 'acme.com' })
          : undefined,
    ]);
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      endpoints: {
        authorization_endpoint: 'https://idp.example/oauth/authorize',
        token_endpoint: 'https://idp.example/oauth/token',
        userinfo_endpoint: 'https://idp.example/oauth/userinfo',
      },
      fetcher: m.fetch,
    });
    const att = await provider.exchangeOrVerify(
      {
        kind: 'oauth_code',
        code: 'CODE',
        redirect_uri: 'https://saas/callback',
        pkce_verifier: 'VERIFIER',
      },
      fakeCtx({ audience: 'aud-z' }),
    );
    expect(att.issuer).toBe('idp');
    expect(att.subject).toBe('user-42');
    expect(att.audience).toBe('aud-z');
    expect(att.display_handle).toBe('Alice');
    expect(att.raw_metadata?.email).toBe('alice@acme.com');
    expect(att.raw_metadata?.hd).toBe('acme.com');
    // Authorization header on userinfo call.
    const userinfoCall = m.calls.find((c) => c.url.includes('userinfo'));
    const auth = new Headers(userinfoCall?.init?.headers).get('authorization');
    expect(auth).toBe('Bearer at_x');
  });

  it('maps token-endpoint error JSON to a 401 AgentAuthError', async () => {
    const m = mockFetch([
      (url) =>
        url.endsWith('/token')
          ? jsonRes(400, { error: 'invalid_grant', error_description: 'expired' })
          : undefined,
    ]);
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      endpoints: {
        authorization_endpoint: 'https://idp.example/a',
        token_endpoint: 'https://idp.example/token',
        userinfo_endpoint: 'https://idp.example/u',
      },
      fetcher: m.fetch,
    });
    await expect(
      provider.exchangeOrVerify(
        {
          kind: 'oauth_code',
          code: 'X',
          redirect_uri: 'https://saas/callback',
          pkce_verifier: 'V',
        },
        fakeCtx(),
      ),
    ).rejects.toThrow(/invalid_grant.*expired/);
  });

  it('rejects userinfo response without `sub`', async () => {
    const m = mockFetch([
      (url) => (url.endsWith('/token') ? jsonRes(200, { access_token: 'at' }) : undefined),
      (url) => (url.endsWith('/userinfo') ? jsonRes(200, { email: 'no-sub@x.com' }) : undefined),
    ]);
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      endpoints: {
        authorization_endpoint: 'https://idp.example/a',
        token_endpoint: 'https://idp.example/token',
        userinfo_endpoint: 'https://idp.example/userinfo',
      },
      fetcher: m.fetch,
    });
    await expect(
      provider.exchangeOrVerify(
        {
          kind: 'oauth_code',
          code: 'X',
          redirect_uri: 'https://saas/callback',
          pkce_verifier: 'V',
        },
        fakeCtx(),
      ),
    ).rejects.toThrow(/userinfo response missing/);
  });
});

describe('OidcProvider — discovery', () => {
  it('fetches /.well-known/openid-configuration lazily and caches the result', async () => {
    const m = mockFetch([
      (url) =>
        url === 'https://idp.example/.well-known/openid-configuration'
          ? jsonRes(200, {
              issuer: 'https://idp.example',
              authorization_endpoint: 'https://idp.example/oauth/authorize',
              token_endpoint: 'https://idp.example/oauth/token',
              userinfo_endpoint: 'https://idp.example/oauth/userinfo',
            })
          : undefined,
    ]);
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      issuer_url: 'https://idp.example',
      fetcher: m.fetch,
    });
    await provider.beginRegistration(fakeCtx());
    await provider.beginRegistration(fakeCtx());
    const discoveryCalls = m.calls.filter((c) =>
      c.url.endsWith('/.well-known/openid-configuration'),
    );
    expect(discoveryCalls.length).toBe(1);
  });

  it('throws AgentAuthError when discovery doc is missing required endpoints', async () => {
    const m = mockFetch([
      (url) =>
        url.endsWith('/.well-known/openid-configuration')
          ? jsonRes(200, { issuer: 'https://idp.example' /* missing endpoints */ })
          : undefined,
    ]);
    const provider = new OidcProvider({
      name: 'idp',
      client_id: 'cid',
      client_secret: 'csec',
      issuer_url: 'https://idp.example',
      fetcher: m.fetch,
    });
    await expect(provider.beginRegistration(fakeCtx())).rejects.toThrow(
      /missing required endpoints/,
    );
  });
});
