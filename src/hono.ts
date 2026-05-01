/**
 * Vouch — Hono integration.
 *
 * Pairs with the framework-agnostic `lifecycle` exposed on the VouchInstance
 * (see `src/factory.ts`). Two top-level helpers mirror the Express variant:
 *
 *   - `honoRoutes(auth)` — returns a Hono router with all 12 lifecycle
 *     routes wired up. Mount with `app.route('/agent-auth', honoRoutes(auth))`.
 *   - `honoAppMiddleware(auth, opts?)` — returns the validate-key middleware
 *     bound to the instance's deps. Mount on protected paths with
 *     `app.use('/api/agent/v1/*', honoAppMiddleware(auth))`.
 *
 * Re-exports `honoMiddleware` (the lower-level middleware that takes
 * ValidateKeyDeps directly) for power users who don't want to go through
 * the factory.
 */

import { Hono } from 'hono';
import type { Context, MiddlewareHandler } from 'hono';
import { createHash } from 'node:crypto';

import type { VouchInstance, VouchRequestContext } from './factory.js';
import { honoMiddleware } from './middleware/hono-adapter.js';
import { makeValidateKeyDeps } from './middleware/validate-key.js';
import type {
  HonoLikeContext,
  HonoMiddlewareOptions,
} from './middleware/hono-adapter.js';
import { AgentAuthError, isAgentAuthError } from './errors.js';
import type { AgentContext } from './types.js';

export {
  honoMiddleware,
  type HonoLikeContext,
  type HonoMiddlewareOptions,
  type HonoAgentMiddleware,
} from './middleware/hono-adapter.js';

// ---------------------------------------------------------------------------
// honoAppMiddleware — middleware bound to a VouchInstance
// ---------------------------------------------------------------------------

/**
 * Validate-key middleware bound to a VouchInstance. Sets `c.set('agent', …)`
 * on success per the Vouch SPEC §6.3 (NOT `c.set('user', …)` — that's your
 * existing human auth's slot).
 */
export function honoAppMiddleware(
  auth: VouchInstance,
  opts: HonoMiddlewareOptions = {},
): MiddlewareHandler {
  // Build a fresh ValidateKeyDeps off the resolved config — this gives the
  // hono path its own LocalCache (separate from auth.express.middleware()
  // if both happen to be mounted in the same process). Sharing the cache
  // across frameworks is a v0.3 nice-to-have.
  const deps = makeValidateKeyDeps(auth.config);
  const inner = honoMiddleware(deps, opts);
  return async (c, next) => {
    const result = await inner(c as unknown as HonoLikeContext, next as () => Promise<void>);
    return result as Response | void;
  };
}

// ---------------------------------------------------------------------------
// honoRoutes — a Hono router for the 12 lifecycle routes
// ---------------------------------------------------------------------------

/**
 * Build a Hono router with all 12 lifecycle routes wired to the
 * VouchInstance. Body parsing is handled per-route (JSON for the standard
 * routes, raw bytes for `/webhooks/:provider` and `/recover-account-confirm/:token`
 * because both verify HMAC against the raw payload).
 */
export function honoRoutes(auth: VouchInstance): Hono {
  const router = new Hono();
  const lc = auth.lifecycle;

  // ---------- Public lifecycle (JSON body) ----------
  router.post('/begin-registration', async (c) => {
    const body = await readJsonBody(c);
    const out = await lc.beginRegistration({
      body,
      request_context: contextFromHono(c),
    });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.get('/callback', async (c) => {
    const provider =
      c.req.query('provider') ??
      auth.config.identity_providers[0]?.name ??
      '';
    const input: Parameters<typeof lc.callback>[0]['input'] = {
      provider,
      state: c.req.query('state') ?? '',
      code: c.req.query('code') ?? '',
      ...(c.req.query('error') ? { error: c.req.query('error')! } : {}),
      ...(c.req.query('error_description')
        ? { error_description: c.req.query('error_description')! }
        : {}),
    };
    const out = await lc.callback({ input, request_context: contextFromHono(c) });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.get('/registration-status', async (c) => {
    const out = await lc.registrationStatus({
      poll_token: c.req.query('poll_token') ?? '',
    });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.post('/recover-account', async (c) => {
    const body = await readJsonBody(c);
    const out = await lc.recoverAccount({
      body,
      request_context: contextFromHono(c),
    });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.get('/recover-account-status', async (c) => {
    const out = await lc.recoverAccountStatus({
      poll_token: c.req.query('poll_token') ?? '',
    });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.get('/healthz', async (c) => {
    const out = await lc.healthz();
    return new Response(JSON.stringify(out.body), {
      status: out.http_status,
      headers: { 'content-type': 'application/json' },
    });
  });

  router.get('/well-known', (c) => {
    const url = new URL(c.req.url);
    const out = lc.wellKnown({ base_url: `${url.protocol}//${url.host}` });
    return c.json(out as unknown as Record<string, unknown>);
  });

  // ---------- Webhook (raw body) ----------
  router.post('/webhooks/:provider', async (c) => {
    const provider = c.req.param('provider');
    const raw_body = Buffer.from(await c.req.arrayBuffer());
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(c.req.header())) {
      headers[k.toLowerCase()] = v;
    }
    const out = await lc.webhook({ provider, headers, raw_body });
    return c.json(out as unknown as Record<string, unknown>);
  });

  // ---------- Recover-confirm (raw body — HMAC-verified) ----------
  router.post('/recover-account-confirm/:token', async (c) => {
    const approval_url_token = c.req.param('token');
    const raw_body = Buffer.from(await c.req.arrayBuffer());
    const headers: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(c.req.header())) {
      headers[k.toLowerCase()] = v;
    }
    const out = await lc.recoverAccountConfirm({
      input: {
        approval_url_token,
        path: new URL(c.req.url).pathname,
        method: 'POST',
        headers,
        raw_body,
      },
    });
    return c.json(out as unknown as Record<string, unknown>);
  });

  // ---------- Authenticated agent-management ----------
  router.post('/rotate-key', async (c) => {
    const agent = await requireAgent(auth, c);
    const body = await readJsonBody(c);
    const idempotency_key = c.req.header('idempotency-key') ?? '';
    const out = await lc.rotateKey({ body, caller: agent, idempotency_key });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.post('/revoke', async (c) => {
    const agent = await requireAgent(auth, c);
    const body = await readJsonBody(c);
    const idempotency_key = c.req.header('idempotency-key') ?? '';
    const out = await lc.revoke({ body, caller: agent, idempotency_key });
    return c.json(out as unknown as Record<string, unknown>);
  });

  router.get('/list-keys', async (c) => {
    const agent = await requireAgent(auth, c);
    const out = await lc.listKeys({ caller: agent });
    return c.json(out as unknown as Record<string, unknown>);
  });

  // ---------- Error formatter ----------
  router.onError((err) => {
    const e = isAgentAuthError(err)
      ? err
      : new AgentAuthError(500, 'internal_error', undefined, { cause: err });
    const body = {
      error: {
        code: e.code,
        message: e.message || e.code,
        ...(e.details ? { details: e.details } : {}),
      },
    };
    return new Response(JSON.stringify(body), {
      status: e.status,
      headers: { 'content-type': 'application/json' },
    });
  });

  return router;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function contextFromHono(c: Context): VouchRequestContext {
  // Hono doesn't expose a stable IP getter cross-runtime, so we read
  // the standard X-Forwarded-For first, fall back to the host header.
  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? '127.0.0.1';
  return {
    ip_hash: createHash('sha256').update(ip).digest(),
    user_agent: c.req.header('user-agent') ?? '',
  };
}

async function readJsonBody(c: Context): Promise<unknown> {
  try {
    return await c.req.json();
  } catch {
    return undefined;
  }
}

async function requireAgent(auth: VouchInstance, c: Context): Promise<AgentContext> {
  const auth_header = c.req.header('authorization');
  if (!auth_header) throw new AgentAuthError(401, 'invalid_key');
  const m = /^Bearer\s+(.+)$/i.exec(auth_header);
  const token = m?.[1]?.trim();
  if (!token) throw new AgentAuthError(401, 'invalid_key');
  return auth.lifecycle.validateBearer(token);
}
