/**
 * Unit tests for GoogleProvider — verifies it constructs an OidcProvider
 * with Google's discovery URL and the optional `hd` query param. Doesn't
 * exercise the full OIDC flow (that's covered in oidc-provider.test.ts);
 * just the Google-specific delta.
 */
import { describe, it, expect } from 'vitest';
import { GoogleProvider } from '../../src/identity/google/provider.js';
import type { AttestationContext } from '../../src/types.js';

function fakeCtx(): AttestationContext {
  return {
    audience: 'aud',
    nonce: 'state',
    poll_token: 'pak_x',
    client_pubkey: new Uint8Array(32),
    ip_hash: Buffer.alloc(32),
    user_agent: 'test',
    redirect_uri: 'https://saas/callback',
    pkce_challenge: 'c',
    pkce_challenge_method: 'S256',
    intent: 'register',
  };
}

function jsonRes(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('GoogleProvider', () => {
  it('uses provider name "google" by default', () => {
    const p = new GoogleProvider({
      client_id: 'c',
      client_secret: 's',
    });
    expect(p.name).toBe('google');
  });

  it('honors a custom name override', () => {
    const p = new GoogleProvider({
      client_id: 'c',
      client_secret: 's',
      name: 'workspace',
    });
    expect(p.name).toBe('workspace');
  });

  it('appends `hd=<domain>` to the authorize URL when hosted_domain is set', async () => {
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return jsonRes(200, {
          issuer: 'https://accounts.google.com',
          authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
          token_endpoint: 'https://oauth2.googleapis.com/token',
          userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
        });
      }
      throw new Error('unexpected fetch in test: ' + url);
    };
    const p = new GoogleProvider({
      client_id: 'cid',
      client_secret: 'csec',
      hosted_domain: 'acme.com',
      fetcher,
    });
    const out = await p.beginRegistration(fakeCtx());
    const url = new URL(out.challenge_url!);
    expect(url.host).toBe('accounts.google.com');
    expect(url.searchParams.get('hd')).toBe('acme.com');
    expect(url.searchParams.get('client_id')).toBe('cid');
  });

  it('discovers Google endpoints via the hardcoded issuer URL', async () => {
    let discovered = false;
    const fetcher: typeof fetch = async (input) => {
      const url = String(input);
      if (url === 'https://accounts.google.com/.well-known/openid-configuration') {
        discovered = true;
        return jsonRes(200, {
          issuer: 'https://accounts.google.com',
          authorization_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
          token_endpoint: 'https://oauth2.googleapis.com/token',
          userinfo_endpoint: 'https://openidconnect.googleapis.com/v1/userinfo',
        });
      }
      throw new Error('unexpected fetch: ' + url);
    };
    const p = new GoogleProvider({
      client_id: 'c',
      client_secret: 's',
      fetcher,
    });
    await p.beginRegistration(fakeCtx());
    expect(discovered).toBe(true);
  });
});
