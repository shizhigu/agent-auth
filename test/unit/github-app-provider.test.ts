import { describe, it, expect } from 'vitest';
import { GitHubAppProvider } from '../../src/identity/github-app/browser-flow.js';
import type { Fetcher } from '../../src/identity/github-app/browser-flow.js';
import type { AttestationContext } from '../../src/types.js';

function makeCtx(overrides: Partial<AttestationContext> = {}): AttestationContext {
  return {
    audience: 'Iv1.abcdef',
    nonce: 'NONCE_VALUE',
    poll_token: 'pak_xxx',
    client_pubkey: Buffer.alloc(32),
    ip_hash: Buffer.alloc(32),
    user_agent: 'test',
    redirect_uri: 'https://saas/callback',
    pkce_challenge: 'CHALLENGE',
    pkce_challenge_method: 'S256',
    intent: 'register',
    ...overrides,
  };
}

describe('GitHubAppProvider.beginRegistration (SPEC §2.2.2)', () => {
  it('builds an authorize URL with state, code_challenge, S256, scope', async () => {
    const provider = new GitHubAppProvider({
      client_id: 'Iv1.abcdef',
      client_secret: 'secret',
      fetcher: (() => {
        throw new Error('no fetch in begin');
      }) as Fetcher,
    });
    const out = await provider.beginRegistration(makeCtx());
    expect(out.challenge_url).toBeDefined();
    const u = new URL(out.challenge_url!);
    expect(u.host).toBe('github.com');
    expect(u.pathname).toBe('/login/oauth/authorize');
    expect(u.searchParams.get('client_id')).toBe('Iv1.abcdef');
    expect(u.searchParams.get('state')).toBe('NONCE_VALUE');
    expect(u.searchParams.get('code_challenge')).toBe('CHALLENGE');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('redirect_uri')).toBe('https://saas/callback');
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('scope')).toBe('read:user');
  });
});

describe('GitHubAppProvider.exchangeOrVerify', () => {
  function makeProviderWithFetch(handler: (req: Request) => Response | Promise<Response>) {
    const fetcher: Fetcher = (input, init) => {
      const url = typeof input === 'string' ? input : input.toString();
      return Promise.resolve(handler(new Request(url, init as RequestInit)));
    };
    return new GitHubAppProvider({
      client_id: 'Iv1.abcdef',
      client_secret: 'secret',
      fetcher,
    });
  }

  it('exchanges code -> access_token, fetches /user, returns Attestation', async () => {
    const provider = makeProviderWithFetch((req) => {
      if (req.url.includes('login/oauth/access_token')) {
        return new Response(
          JSON.stringify({ access_token: 'tok_xxx', token_type: 'bearer', scope: 'read:user' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (req.url.endsWith('/user')) {
        return new Response(
          JSON.stringify({ id: 12345, login: 'octocat', type: 'User' }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      return new Response('not found', { status: 404 });
    });
    const att = await provider.exchangeOrVerify(
      {
        kind: 'oauth_code',
        code: 'CODE',
        redirect_uri: 'https://saas/callback',
        pkce_verifier: 'VERIFIER',
      },
      makeCtx(),
    );
    expect(att).toEqual({
      issuer: 'github.com',
      subject: '12345',
      audience: 'Iv1.abcdef',
      display_handle: 'octocat',
      assurance_level: 'medium',
      supports_revalidation: true,
      raw_metadata: { type: 'User' },
    });
  });

  it('rejects when GitHub returns an OAuth error', async () => {
    const provider = makeProviderWithFetch(() =>
      new Response(
        JSON.stringify({ error: 'bad_verification_code', error_description: 'expired' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
    await expect(
      provider.exchangeOrVerify(
        {
          kind: 'oauth_code',
          code: 'X',
          redirect_uri: 'https://saas/callback',
          pkce_verifier: 'V',
        },
        makeCtx(),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_request' });
  });

  it('rejects redirect_uri mismatch (defense in depth)', async () => {
    const provider = makeProviderWithFetch(() => new Response('{}', { status: 200 }));
    await expect(
      provider.exchangeOrVerify(
        {
          kind: 'oauth_code',
          code: 'X',
          redirect_uri: 'https://attacker',
          pkce_verifier: 'V',
        },
        makeCtx({ redirect_uri: 'https://saas/callback' }),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_request' });
  });

  it('rejects non-oauth_code input', async () => {
    const provider = makeProviderWithFetch(() => new Response('{}', { status: 200 }));
    await expect(
      provider.exchangeOrVerify(
        { kind: 'attestation_jwt', token: 'X' },
        makeCtx(),
      ),
    ).rejects.toMatchObject({ status: 400, code: 'invalid_request' });
  });
});

describe('GitHubAppProvider.revalidate', () => {
  it('returns still_valid=false for unknown provider', async () => {
    const provider = new GitHubAppProvider({
      client_id: 'Iv1.abcdef',
      client_secret: 'secret',
    });
    expect(
      await provider.revalidate({
        provider: 'other',
        subject: 's',
        audience: 'Iv1.abcdef',
      }),
    ).toEqual({ still_valid: false });
  });

  it('returns still_valid=true when no app key is configured (no-op)', async () => {
    const provider = new GitHubAppProvider({
      client_id: 'Iv1.abcdef',
      client_secret: 'secret',
    });
    expect(
      await provider.revalidate({
        provider: 'github_app',
        subject: '12345',
        audience: 'Iv1.abcdef',
      }),
    ).toEqual({ still_valid: true });
  });
});
