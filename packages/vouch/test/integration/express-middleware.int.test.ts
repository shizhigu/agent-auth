/**
 * Integration: Express middleware end-to-end against real Postgres + Redis.
 * SPEC §6.3 (req.agent / confused-deputy) + §10.3 (error wire shape) +
 * §10.5 (X-Request-Id headers).
 *
 * Spins up a real Express server, mounts `expressMiddleware` against a
 * live DB, and drives requests via `fetch`. Validates the full HTTP
 * round-trip:
 *   - 200 happy path with req.agent populated and X-Request-Id echoed.
 *   - 401 invalid_key when bearer is malformed.
 *   - 401 invalid_secret when secret HMAC fails.
 *   - X-Request-Id is preserved verbatim from the inbound header.
 *   - downstream route can call require_scope and the SaaS error handler
 *     turns the thrown AgentAuthError into a §10.3 JSON body.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import express from 'express';
import type { ErrorRequestHandler, Request, Response } from 'express';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import {
  expressMiddleware,
  makeValidateKeyDeps,
} from '../../src/index.js';
import { resolveConfig } from '../../src/config.js';
import type { AgentContext, IdentityProvider } from '../../src/types.js';
import { isAgentAuthError } from '../../src/errors.js';
import type { Server } from 'node:http';

class StubProvider implements IdentityProvider {
  readonly name = 'github_app';
  async beginRegistration() {
    return {};
  }
  async exchangeOrVerify(): Promise<never> {
    throw new Error('not used');
  }
  async revalidate() {
    return { still_valid: true };
  }
}

describe('integration: Express middleware (SPEC §6.3 / §10.3 / §10.5)', () => {
  let fix: IntegrationFixture;
  let server: Server;
  let url: string;
  let bearer: string;
  let key_id: string;
  let account_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();

    // Seed account + identity + key.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('exp-int', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'exp-int-1', 'Iv1.exp', 'github.com', 'medium',
                 'exp-int-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    account_id = acc!.id;
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    key_id = `agk_${randomBytes(6).toString('base64url')}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;

    // Build the lib config + middleware against the real fixture.
    const config = resolveConfig({
      internal_secret: Buffer.alloc(32, 0xab),
      identity_providers: [new StubProvider()],
      storage: { postgres: fix.postgres, redis: fix.redis, kms: fix.kms },
      validation: {
        mode: 'strict_uncached',
        local_cache_capacity: 100,
        local_cache_ttl_ms: 30_000,
        redis_cache_ttl_seconds: 30,
      },
    });
    const deps = makeValidateKeyDeps(config);
    const mw = expressMiddleware(deps, {
      docs_url_base: 'https://saas/docs/agent-auth/errors',
    });

    const app = express();
    app.use('/api/agent/v1', mw);
    app.get('/api/agent/v1/data', (req: Request, res: Response) => {
      const agent = (req as Request & { agent?: AgentContext }).agent;
      if (!agent) return res.status(500).end();
      agent.require_scope('read'); // throws AgentAuthError(403) if missing
      return res.json({ account_id: agent.account_id, key_id: agent.key_id });
    });
    app.get('/api/agent/v1/admin', (req: Request, res: Response) => {
      const agent = (req as Request & { agent?: AgentContext }).agent;
      if (!agent) return res.status(500).end();
      agent.require_scope('admin'); // will throw 403
      return res.json({ ok: true });
    });
    // Translate route-thrown AgentAuthError into the §10.3 wire shape.
    const onErr: ErrorRequestHandler = (err, req, res, _next) => {
      void req;
      if (isAgentAuthError(err)) {
        const body = err.toJSON();
        const xrid = res.getHeader('X-Request-Id');
        if (xrid) (body.error as { request_id?: string }).request_id = String(xrid);
        return res.status(err.status).json(body);
      }
      return res.status(500).json({ error: { code: 'internal_error' } });
    };
    app.use(onErr);

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => resolve());
    });
    const addr = server.address();
    if (!addr || typeof addr !== 'object') throw new Error('no address');
    url = `http://127.0.0.1:${addr.port}`;
  }, 240_000);

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await fix.cleanup();
  }, 120_000);

  it('200 happy path: req.agent populated; X-Request-Id echoed', async () => {
    const res = await fetch(`${url}/api/agent/v1/data`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-request-id')).toBeTruthy();
    const body = (await res.json()) as { account_id: string; key_id: string };
    expect(body).toEqual({ account_id, key_id });
  });

  it('inbound X-Request-Id is preserved verbatim', async () => {
    const reqId = 'req-test-12345';
    const res = await fetch(`${url}/api/agent/v1/data`, {
      headers: {
        authorization: `Bearer ${bearer}`,
        'x-request-id': reqId,
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-request-id')).toBe(reqId);
  });

  it('401 invalid_key on missing Authorization header', async () => {
    const res = await fetch(`${url}/api/agent/v1/data`);
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string; documentation_url?: string } };
    expect(body.error.code).toBe('invalid_key');
    expect(body.error.documentation_url).toBe(
      'https://saas/docs/agent-auth/errors#invalid_key',
    );
  });

  it('401 invalid_secret on tampered secret', async () => {
    const tampered = `${key_id}.${randomBytes(32).toString('base64url')}`;
    const res = await fetch(`${url}/api/agent/v1/data`, {
      headers: { authorization: `Bearer ${tampered}` },
    });
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe('invalid_secret');
  });

  it('403 insufficient_scope from route-thrown AgentAuthError', async () => {
    const res = await fetch(`${url}/api/agent/v1/admin`, {
      headers: { authorization: `Bearer ${bearer}` },
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      error: { code: string; details?: { required: string }; request_id?: string };
    };
    expect(body.error.code).toBe('insufficient_scope');
    expect(body.error.details?.required).toBe('admin');
    expect(body.error.request_id).toBeDefined();
  });
});
