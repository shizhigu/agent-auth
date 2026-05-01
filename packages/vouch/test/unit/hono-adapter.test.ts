import { describe, it, expect, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import { Hono } from 'hono';
import { honoMiddleware } from '../../src/middleware/hono-adapter.js';
import type { ValidateKeyDeps } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type {
  AccountStatus,
  AgentContext,
  IdentityStatus,
  RotationState,
} from '../../src/types.js';

interface FakeRow {
  key_id: string;
  account_id: string;
  account_status: AccountStatus;
  account_tier: 'cold' | 'warm' | 'hot';
  issued_via_identity_id: string;
  issuing_identity_status: IdentityStatus;
  identity_provider: string;
  identity_subject: string;
  identity_display_handle: string | null;
  identity_assurance_level: 'low' | 'medium' | 'high';
  key_hash: Buffer;
  key_pepper_version: number;
  scopes: string[];
  tier: 'cold' | 'warm' | 'hot';
  rotation_state: RotationState;
  revoked_at: Date | null;
  rotation_grace_expires_at: Date | null;
  expires_at: Date | null;
}

class FakePg {
  rows = new Map<string, FakeRow>();
  async queryOne<R>(_t: string, params: ReadonlyArray<unknown>): Promise<R | null> {
    return ((this.rows.get(params[0] as string) ?? null) as unknown as R | null);
  }
  // validate-key best-effort last_used_at UPDATE — no-op.
  async query(_t: string, _params?: ReadonlyArray<unknown>): Promise<{ rows: unknown[] }> {
    return { rows: [] };
  }
}

async function buildDeps(): Promise<{
  deps: ValidateKeyDeps;
  presented: string;
}> {
  const kms = new InMemoryKmsAdapter();
  const redis = new InMemoryRedisAdapter();
  const pg = new FakePg();
  const localCache = new LocalCache();
  const secret = randomBytes(32);
  const pepper = await kms.getCurrentPepper();
  const key_hash = hmacWithPepper(pepper.data, secret);
  pg.rows.set('agk_h0n0', {
    key_id: 'agk_h0n0',
    account_id: 'acc-h',
    account_status: 'active',
    account_tier: 'cold',
    issued_via_identity_id: 'id-h',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: '999',
    identity_display_handle: 'hono-octocat',
    identity_assurance_level: 'medium',
    key_hash,
    key_pepper_version: 1,
    scopes: ['read', 'self:rotate'],
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    rotation_grace_expires_at: null,
    expires_at: null,
  });
  return {
    deps: {
      postgres: pg as unknown as PostgresAdapter,
      redis,
      kms,
      localCache,
      redis_cache_ttl_seconds: 30,
    },
    presented: 'agk_h0n0.' + secret.toString('base64url'),
  };
}

describe('honoMiddleware', () => {
  let deps: ValidateKeyDeps;
  let presented: string;

  beforeEach(async () => {
    ({ deps, presented } = await buildDeps());
  });

  it('happy path: c.get("agent") is the AgentContext; X-Request-Id echoed (SPEC §10.5)', async () => {
    const app = new Hono();
    app.use('/protected', honoMiddleware(deps));
    app.get('/protected', (c) => {
      const agent = c.get('agent') as AgentContext;
      return c.json({ account_id: agent.account_id });
    });

    const res = await app.request('/protected', {
      headers: { authorization: `Bearer ${presented}` },
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ account_id: 'acc-h' });
    expect(res.headers.get('x-request-id')).toBeTruthy();
  });

  it('inbound X-Request-Id is preserved verbatim on success (SPEC §10.5)', async () => {
    const app = new Hono();
    app.use('/protected', honoMiddleware(deps));
    app.get('/protected', (c) => c.json({ ok: true }));
    const reqId = 'req-hono-12345';
    const res = await app.request('/protected', {
      headers: {
        authorization: `Bearer ${presented}`,
        'x-request-id': reqId,
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-request-id')).toBe(reqId);
  });

  it('returns 401 invalid_key when bearer is missing', async () => {
    const app = new Hono();
    app.use('/protected', honoMiddleware(deps));
    app.get('/protected', (c) => c.text('ok'));

    const res = await app.request('/protected');
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('invalid_key');
    expect(res.headers.get('x-request-id')).toBeTruthy();
  });

  it('route-thrown AgentAuthError surfaces via Hono onError handler', async () => {
    // Hono runs `app.onError` for uncaught throws. The lib does not install
    // a global error handler, so the SaaS app does this once at startup.
    const app = new Hono();
    app.onError((err, c) => {
      if (err && typeof err === 'object' && 'code' in err && 'status' in err) {
        const e = err as { status: number; code: string };
        return c.json({ error: { code: e.code, message: e.code } }, e.status as 200);
      }
      return c.text('boom', 500);
    });
    app.use('/protected', honoMiddleware(deps));
    app.get('/protected', (c) => {
      const agent = c.get('agent') as AgentContext;
      agent.require_scope('admin');
      return c.text('ok');
    });

    const res = await app.request('/protected', {
      headers: { authorization: `Bearer ${presented}` },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('insufficient_scope');
  });

  it('echoes inbound X-Request-Id on errors', async () => {
    const app = new Hono();
    app.use('/protected', honoMiddleware(deps));
    app.get('/protected', (c) => c.text('ok'));

    const res = await app.request('/protected', {
      headers: { 'x-request-id': 'reqq-42' },
    });
    expect(res.status).toBe(401);
    expect(res.headers.get('x-request-id')).toBe('reqq-42');
  });

  it('docs_url_base is appended on errors', async () => {
    const app = new Hono();
    app.use(
      '/protected',
      honoMiddleware(deps, { docs_url_base: 'https://saas/docs/agent-auth/errors' }),
    );
    app.get('/protected', (c) => c.text('ok'));

    const res = await app.request('/protected');
    const body = (await res.json()) as { error: { documentation_url?: string } };
    expect(body.error.documentation_url).toBe(
      'https://saas/docs/agent-auth/errors#invalid_key',
    );
  });
});
