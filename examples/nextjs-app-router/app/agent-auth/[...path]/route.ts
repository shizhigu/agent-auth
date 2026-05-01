/**
 * Vouch on Next.js (App Router) — catch-all Route Handler.
 *
 * Drop this file at:
 *
 *   app/agent-auth/[...path]/route.ts
 *
 * It dispatches every method (GET / POST) under `/agent-auth/*` to the
 * Vouch lifecycle. For your protected API routes, see
 * `app/api/agent/v1/[...]/route.ts` further down.
 *
 * Why directly use `auth.lifecycle` instead of `auth.express.handler()`:
 * Next.js Route Handlers receive a Web `Request` and return a `Response`,
 * not (req, res, next). The framework-agnostic lifecycle layer is the
 * cleanest fit; you wire each route as a thin Web-Request adapter.
 *
 * Required deps (install in your Next.js app):
 *   npm install @vouch/server pg ioredis @aws-sdk/client-kms libsodium-wrappers
 *
 * Type imports below assume `next` is installed (peer dep of any
 * Next.js app).
 */

import { NextRequest, NextResponse } from 'next/server';
import { vouch, type VouchInstance } from '@vouch/server';

// --------------------------------------------------------------------------
// 1. Build a single Vouch instance and reuse it across requests.
//
// Next.js's App Router caches module-scope state per server instance, so
// `vouch()` runs once per cold-start (per worker, per Vercel function
// instance). The Postgres / Redis pools live for the function's lifetime.
// --------------------------------------------------------------------------

let _auth: Promise<VouchInstance> | null = null;
function getAuth(): Promise<VouchInstance> {
  if (_auth) return _auth;
  _auth = vouch({
    database: { url: process.env.DATABASE_URL! },
    redis: { url: process.env.REDIS_URL! },
    kms: {
      provider: 'aws',
      region: process.env.AWS_REGION ?? 'us-east-1',
      pepper_alias: process.env.KMS_PEPPER_ALIAS!,
      device_alias: process.env.KMS_DEVICE_ALIAS!,
      pepperFetcher: async (_v) => {
        // TODO: read pepper bytes from KMS / SSM / your secret store.
        throw new Error('pepperFetcher not implemented');
      },
    },
    identity: {
      github: {
        client_id: process.env.GH_CLIENT_ID!,
        client_secret: process.env.GH_CLIENT_SECRET!,
        webhook_secret: process.env.GH_WEBHOOK_SECRET!,
        app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
      },
    },
    internal_secret: process.env.AGENT_AUTH_INTERNAL_SECRET!,
    base_url: process.env.PUBLIC_BASE_URL!,
  });
  return _auth;
}

// --------------------------------------------------------------------------
// 2. Catch-all dispatcher.
//
// Next.js App Router calls the exported function matching the HTTP method
// (GET, POST, etc). Both delegate into one helper.
// --------------------------------------------------------------------------

interface Ctx {
  params: { path: string[] };
}

export async function GET(req: NextRequest, ctx: Ctx) {
  return dispatch(req, ctx);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  return dispatch(req, ctx);
}

async function dispatch(req: NextRequest, ctx: Ctx): Promise<NextResponse> {
  const auth = await getAuth();
  const lc = auth.lifecycle;
  const subpath = '/' + (ctx.params.path?.join('/') ?? '');
  const requestContext = {
    ip_hash: hash(req.headers.get('x-forwarded-for') ?? '127.0.0.1'),
    user_agent: req.headers.get('user-agent') ?? '',
  };

  try {
    if (subpath === '/begin-registration' && req.method === 'POST') {
      const body = await req.json();
      return NextResponse.json(
        await lc.beginRegistration({ body, request_context: requestContext }),
      );
    }

    if (subpath === '/callback' && req.method === 'GET') {
      const url = new URL(req.url);
      const provider = url.searchParams.get('provider') ?? 'github_app';
      const out = await lc.callback({
        input: {
          provider,
          state: url.searchParams.get('state') ?? '',
          code: url.searchParams.get('code') ?? '',
          ...(url.searchParams.get('error')
            ? { error: url.searchParams.get('error')! }
            : {}),
          ...(url.searchParams.get('error_description')
            ? { error_description: url.searchParams.get('error_description')! }
            : {}),
        },
        request_context: requestContext,
      });
      return NextResponse.json(out);
    }

    if (subpath === '/registration-status' && req.method === 'GET') {
      const url = new URL(req.url);
      return NextResponse.json(
        await lc.registrationStatus({ poll_token: url.searchParams.get('poll_token') ?? '' }),
      );
    }

    if (subpath === '/healthz' && req.method === 'GET') {
      const out = await lc.healthz();
      return NextResponse.json(out.body, { status: out.http_status });
    }

    if (subpath === '/well-known' && req.method === 'GET') {
      const url = new URL(req.url);
      return NextResponse.json(lc.wellKnown({ base_url: url.origin }));
    }

    // Webhook needs raw body; Next.js gives it via req.text() / req.arrayBuffer().
    if (subpath.startsWith('/webhooks/') && req.method === 'POST') {
      const provider = subpath.slice('/webhooks/'.length);
      const raw_body = Buffer.from(await req.arrayBuffer());
      const headers: Record<string, string> = {};
      req.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return NextResponse.json(await lc.webhook({ provider, headers, raw_body }));
    }

    // Authenticated routes — validate Bearer first.
    if (
      (subpath === '/rotate-key' && req.method === 'POST') ||
      (subpath === '/revoke' && req.method === 'POST') ||
      (subpath === '/list-keys' && req.method === 'GET')
    ) {
      const bearer = extractBearer(req.headers.get('authorization'));
      if (!bearer) return jsonError(401, 'invalid_key');
      const caller = await lc.validateBearer(bearer);
      const idempotency_key = req.headers.get('idempotency-key') ?? '';

      if (subpath === '/rotate-key') {
        const body = await req.json();
        return NextResponse.json(await lc.rotateKey({ body, caller, idempotency_key }));
      }
      if (subpath === '/revoke') {
        const body = await req.json();
        return NextResponse.json(await lc.revoke({ body, caller, idempotency_key }));
      }
      return NextResponse.json(await lc.listKeys({ caller }));
    }

    return jsonError(404, 'invalid_request', `unknown path: ${subpath}`);
  } catch (err) {
    return mapError(err);
  }
}

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

function hash(s: string): Buffer {
  // Edge-runtime-friendly: use Web Crypto via Buffer round-trip if needed.
  // For Node runtime this is fine.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require('node:crypto') as typeof import('node:crypto');
  return createHash('sha256').update(s).digest();
}

function extractBearer(auth: string | null): string | null {
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  return m?.[1]?.trim() ?? null;
}

function jsonError(status: number, code: string, message?: string): NextResponse {
  return NextResponse.json({ error: { code, message: message ?? code } }, { status });
}

function mapError(err: unknown): NextResponse {
  const e = err as { status?: number; code?: string; message?: string };
  return NextResponse.json(
    { error: { code: e.code ?? 'internal', message: e.message ?? 'Internal error' } },
    { status: e.status ?? 500 },
  );
}
