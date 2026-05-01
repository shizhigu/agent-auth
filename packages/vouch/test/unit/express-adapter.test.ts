import { describe, it, expect, beforeEach } from 'vitest';
import { randomBytes } from 'node:crypto';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { expressMiddleware } from '../../src/middleware/express-adapter.js';
import type { ValidateKeyDeps } from '../../src/middleware/validate-key.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { InMemoryRedisAdapter } from '../../src/storage/redis-adapter.js';
import { InMemoryKmsAdapter } from '../../src/storage/kms-adapter.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { AccountStatus, IdentityStatus, RotationState } from '../../src/types.js';
import type { AgentContext } from '../../src/types.js';

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
  rows: Map<string, FakeRow> = new Map();
  async queryOne<R>(_t: string, params: ReadonlyArray<unknown>): Promise<R | null> {
    return ((this.rows.get(params[0] as string) ?? null) as unknown as R | null);
  }
}

async function setup(): Promise<{
  deps: ValidateKeyDeps;
  presented: string;
  pg: FakePg;
}> {
  const kms = new InMemoryKmsAdapter();
  const redis = new InMemoryRedisAdapter();
  const pg = new FakePg();
  const localCache = new LocalCache();
  const secret = randomBytes(32);
  const pepper = await kms.getCurrentPepper();
  const key_hash = hmacWithPepper(pepper.data, secret);
  pg.rows.set('agk_abc12345', {
    key_id: 'agk_abc12345',
    account_id: 'acc-1',
    account_status: 'active',
    account_tier: 'cold',
    issued_via_identity_id: 'id-1',
    issuing_identity_status: 'active',
    identity_provider: 'github_app',
    identity_subject: '12345',
    identity_display_handle: 'octocat',
    identity_assurance_level: 'medium',
    key_hash,
    key_pepper_version: 1,
    scopes: ['read'],
    tier: 'cold',
    rotation_state: 'active',
    revoked_at: null,
    rotation_grace_expires_at: null,
    expires_at: null,
  });
  const deps: ValidateKeyDeps = {
    postgres: pg as unknown as PostgresAdapter,
    redis,
    kms,
    localCache,
    redis_cache_ttl_seconds: 30,
  };
  return { deps, presented: 'agk_abc12345.' + secret.toString('base64url'), pg };
}

interface JsonResponse {
  status: number;
  body: { error: { code: string; message: string; request_id: string; documentation_url?: string } };
  headers: Record<string, string>;
}

function callMiddleware(
  middleware: ReturnType<typeof expressMiddleware>,
  headers: Record<string, string> = {},
): Promise<{ accepted: boolean; agent?: AgentContext; resp?: JsonResponse }> {
  return new Promise((resolve) => {
    const status: { code: number } = { code: 200 };
    const body: { value: unknown } = { value: undefined };
    const respHeaders: Record<string, string> = {};
    const req = { headers, agent: undefined } as unknown as Request;
    const res = {
      headersSent: false,
      status(c: number) {
        status.code = c;
        return res;
      },
      setHeader(name: string, value: string) {
        respHeaders[name] = value;
      },
      json(b: unknown) {
        body.value = b;
        return res;
      },
    } as unknown as Response;
    const next: NextFunction = () => {
      const agent = req.agent;
      resolve(agent ? { accepted: true, agent } : { accepted: true });
    };
    void middleware(
      req as unknown as Parameters<typeof middleware>[0],
      res as unknown as Parameters<typeof middleware>[1],
      next,
    );
    // Wait one tick so the async middleware can finish on rejection.
    setTimeout(() => {
      if (status.code !== 200) {
        resolve({
          accepted: false,
          resp: {
            status: status.code,
            body: body.value as JsonResponse['body'],
            headers: respHeaders,
          },
        });
      }
    }, 5);
  });
}

describe('expressMiddleware', () => {
  let deps: ValidateKeyDeps;
  let presented: string;

  beforeEach(async () => {
    ({ deps, presented } = await setup());
  });

  it('happy path: req.agent is set; next() called; X-Request-Id echoed', async () => {
    let observedRequestId = '';
    const mw = expressMiddleware(deps, {
      onAccept: (_ctx, rid) => {
        observedRequestId = rid;
      },
    });
    const out = await callMiddleware(mw, {
      authorization: `Bearer ${presented}`,
    });
    expect(out.accepted).toBe(true);
    expect(out.agent?.account_id).toBe('acc-1');
    expect(observedRequestId.length).toBeGreaterThan(0);
  });

  it('echoes inbound X-Request-Id when present', async () => {
    let seen = '';
    const mw = expressMiddleware(deps, { onAccept: (_c, rid) => { seen = rid; } });
    await callMiddleware(mw, {
      authorization: `Bearer ${presented}`,
      'x-request-id': 'req-abc',
    });
    expect(seen).toBe('req-abc');
  });

  it('returns 401 invalid_key on missing Authorization header', async () => {
    const mw = expressMiddleware(deps);
    const out = await callMiddleware(mw, {});
    expect(out.accepted).toBe(false);
    expect(out.resp?.status).toBe(401);
    expect(out.resp?.body.error.code).toBe('invalid_key');
    expect(out.resp?.headers['X-Request-Id']).toBeDefined();
  });

  it('returns 401 invalid_key on malformed bearer', async () => {
    const mw = expressMiddleware(deps);
    const out = await callMiddleware(mw, { authorization: 'Bearer not-a-real-key' });
    expect(out.accepted).toBe(false);
    expect(out.resp?.status).toBe(401);
    expect(out.resp?.body.error.code).toBe('invalid_key');
  });

  it('attaches docs_url_base to error body', async () => {
    const mw = expressMiddleware(deps, { docs_url_base: 'https://saas/docs/agent-auth/errors' });
    const out = await callMiddleware(mw, {});
    expect(out.resp?.body.error.documentation_url).toBe(
      'https://saas/docs/agent-auth/errors#invalid_key',
    );
  });

  it('end-to-end: integrates with a real Express app', async () => {
    const app = express();
    const mw = expressMiddleware(deps);
    app.get('/protected', mw, (req, res) => {
      const agent = (req as Request & { agent?: AgentContext }).agent!;
      res.json({ account_id: agent.account_id, key_id: agent.key_id });
    });
    const server = app.listen(0);
    const address = server.address();
    if (!address || typeof address !== 'object') throw new Error('address');
    const port = address.port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/protected`, {
        headers: { authorization: `Bearer ${presented}` },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('x-request-id')).toBeTruthy();
      const body = (await res.json()) as { account_id: string; key_id: string };
      expect(body).toEqual({ account_id: 'acc-1', key_id: 'agk_abc12345' });

      const bad = await fetch(`http://127.0.0.1:${port}/protected`);
      expect(bad.status).toBe(401);
      const errBody = (await bad.json()) as { error: { code: string } };
      expect(errBody.error.code).toBe('invalid_key');
    } finally {
      server.close();
    }
  });
});
