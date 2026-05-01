/**
 * Unit tests for the @vouch hono helpers.
 *
 * Lightly exercises the route shape — does the Hono router accept the 12
 * lifecycle paths and dispatch them through `auth.lifecycle`? The router is
 * built against a stub VouchInstance whose lifecycle returns canned values;
 * we don't try to spin up a real Postgres or Redis.
 */
import { describe, it, expect } from 'vitest';
import { honoRoutes } from '../../src/hono.js';
import type { VouchInstance, VouchLifecycle } from '../../src/factory.js';

function stubLifecycle(): VouchLifecycle {
  // Each method returns a marker object so the test can assert dispatch.
  return {
    beginRegistration: async ({ body }) => ({ called: 'begin', body }) as never,
    callback: async ({ input }) => ({ called: 'callback', input }) as never,
    registrationStatus: async ({ poll_token }) => ({ called: 'status', poll_token }) as never,
    recoverAccount: async ({ body }) => ({ called: 'recover', body }) as never,
    recoverAccountConfirm: async ({ input }) => ({ called: 'recover-confirm', token: input.approval_url_token }) as never,
    recoverAccountStatus: async ({ poll_token }) => ({ called: 'recover-status', poll_token }) as never,
    rotateKey: async ({ caller }) => ({ called: 'rotate', account: caller.account_id }) as never,
    revoke: async ({ caller }) => ({ called: 'revoke', account: caller.account_id }) as never,
    listKeys: async ({ caller }) => ({ called: 'list', account: caller.account_id }) as never,
    webhook: async ({ provider }) => ({ called: 'webhook', provider }) as never,
    healthz: async () => ({ http_status: 200, body: { status: 'healthy' } }) as never,
    wellKnown: ({ base_url }) => ({ called: 'well-known', base_url }) as never,
    validateBearer: async (token) =>
      ({
        account_id: 'acc-stub',
        key_id: 'k',
        identity: { provider: 'p', subject: 's', assurance_level: 'medium' as const },
        scopes: ['read', 'self:rotate', 'self:revoke', 'admin:keys'],
        tier: 'cold',
        has_scope: () => true,
        require_scope: () => undefined,
      }) as never,
  };
}

function stubInstance(): VouchInstance {
  return {
    config: {
      identity_providers: [{ name: 'stub' } as never],
      validation: { mode: 'strict_uncached' as const },
    } as never,
    adapters: {} as never,
    lifecycle: stubLifecycle(),
    express: {} as never,
    shutdown: async () => {},
  };
}

describe('honoRoutes()', () => {
  it('dispatches GET /well-known via lifecycle.wellKnown', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/well-known');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string };
    expect(body.called).toBe('well-known');
  });

  it('dispatches POST /begin-registration with JSON body', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/begin-registration', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ provider: 'stub', intent: 'register', client_pubkey: 'x' }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; body: { provider: string } };
    expect(body.called).toBe('begin');
    expect(body.body.provider).toBe('stub');
  });

  it('dispatches GET /callback and forwards query params as the input', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/callback?state=xyz&code=abc');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; input: { state: string; code: string } };
    expect(body.called).toBe('callback');
    expect(body.input.state).toBe('xyz');
    expect(body.input.code).toBe('abc');
  });

  it('dispatches GET /registration-status', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/registration-status?poll_token=pak_x');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; poll_token: string };
    expect(body.called).toBe('status');
    expect(body.poll_token).toBe('pak_x');
  });

  it('dispatches POST /webhooks/:provider with raw body', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/webhooks/github_app', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"raw":"payload"}',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; provider: string };
    expect(body.called).toBe('webhook');
    expect(body.provider).toBe('github_app');
  });

  it('dispatches POST /recover-account-confirm/:token', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/recover-account-confirm/abc123', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; token: string };
    expect(body.called).toBe('recover-confirm');
    expect(body.token).toBe('abc123');
  });

  it('GET /healthz uses the right HTTP status from the result', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/healthz');
    expect(res.status).toBe(200);
  });

  it('authenticated routes (POST /rotate-key) require a Bearer header', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/rotate-key', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(401);
  });

  it('authenticated routes succeed when Bearer is supplied', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/rotate-key', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer pak_demo' },
      body: '{}',
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { called: string; account: string };
    expect(body.called).toBe('rotate');
    expect(body.account).toBe('acc-stub');
  });

  it('unhandled paths fall through (404 from Hono)', async () => {
    const router = honoRoutes(stubInstance());
    const res = await router.request('http://saas.example/no-such-route');
    expect(res.status).toBe(404);
  });
});
