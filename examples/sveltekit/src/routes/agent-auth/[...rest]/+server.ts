/**
 * Vouch on SvelteKit — catch-all endpoint for /agent-auth/*.
 *
 * Drop at: src/routes/agent-auth/[...rest]/+server.ts
 *
 * Required deps in your SvelteKit app:
 *   npm install agent-auth pg ioredis @aws-sdk/client-kms libsodium-wrappers
 *
 * SvelteKit endpoints receive a Web `Request`/`Response` event, the
 * same shape as Cloudflare Workers — so `auth.lifecycle.*` is the
 * cleanest fit.
 */
import type { RequestHandler } from '@sveltejs/kit';
import { json, error } from '@sveltejs/kit';
import { vouch, type VouchInstance } from 'agent-auth';
import { env } from '$env/dynamic/private';

let _auth: Promise<VouchInstance> | null = null;
function getAuth(): Promise<VouchInstance> {
  if (_auth) return _auth;
  _auth = vouch({
    database: { url: env.DATABASE_URL! },
    redis: { url: env.REDIS_URL! },
    kms: {
      provider: 'aws',
      region: env.AWS_REGION ?? 'us-east-1',
      pepper_alias: env.KMS_PEPPER_ALIAS!,
      device_alias: env.KMS_DEVICE_ALIAS!,
      pepperFetcher: async (_v) => {
        throw new Error('pepperFetcher not implemented');
      },
    },
    identity: {
      github: {
        client_id: env.GH_CLIENT_ID!,
        client_secret: env.GH_CLIENT_SECRET!,
        webhook_secret: env.GH_WEBHOOK_SECRET!,
        app_private_key_pem: env.GH_APP_PRIVATE_KEY!,
      },
    },
    internal_secret: env.AGENT_AUTH_INTERNAL_SECRET!,
    base_url: env.PUBLIC_BASE_URL!,
  });
  return _auth;
}

const handler: RequestHandler = async ({ request, params, url, getClientAddress }) => {
  const auth = await getAuth();
  const lc = auth.lifecycle;
  const subpath = '/' + (params.rest ?? '');

  // SvelteKit gives client IP via getClientAddress; user agent via header.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { createHash } = require('node:crypto') as typeof import('node:crypto');
  const ctx = {
    ip_hash: createHash('sha256').update(getClientAddress()).digest(),
    user_agent: request.headers.get('user-agent') ?? '',
  };

  try {
    if (subpath === '/begin-registration' && request.method === 'POST') {
      const body = await request.json();
      return json(await lc.beginRegistration({ body, request_context: ctx }));
    }
    if (subpath === '/callback' && request.method === 'GET') {
      const provider = url.searchParams.get('provider') ?? 'github_app';
      const out = await lc.callback({
        input: {
          provider,
          state: url.searchParams.get('state') ?? '',
          code: url.searchParams.get('code') ?? '',
          ...(url.searchParams.get('error') ? { error: url.searchParams.get('error')! } : {}),
          ...(url.searchParams.get('error_description')
            ? { error_description: url.searchParams.get('error_description')! }
            : {}),
        },
        request_context: ctx,
      });
      return json(out);
    }
    if (subpath === '/registration-status' && request.method === 'GET') {
      return json(
        await lc.registrationStatus({ poll_token: url.searchParams.get('poll_token') ?? '' }),
      );
    }
    if (subpath === '/healthz' && request.method === 'GET') {
      const out = await lc.healthz();
      return new Response(JSON.stringify(out.body), {
        status: out.http_status,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (subpath === '/well-known' && request.method === 'GET') {
      return json(lc.wellKnown({ base_url: url.origin }));
    }
    if (subpath.startsWith('/webhooks/') && request.method === 'POST') {
      const provider = subpath.slice('/webhooks/'.length);
      const raw_body = Buffer.from(await request.arrayBuffer());
      const headers: Record<string, string> = {};
      request.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      return json(await lc.webhook({ provider, headers, raw_body }));
    }

    // Authenticated routes.
    if (
      (subpath === '/rotate-key' && request.method === 'POST') ||
      (subpath === '/revoke' && request.method === 'POST') ||
      (subpath === '/list-keys' && request.method === 'GET')
    ) {
      const m = /^Bearer\s+(.+)$/i.exec(request.headers.get('authorization') ?? '');
      const bearer = m?.[1]?.trim();
      if (!bearer) throw error(401, { message: 'invalid_key' });
      const caller = await lc.validateBearer(bearer);
      const idempotency_key = request.headers.get('idempotency-key') ?? '';
      if (subpath === '/rotate-key') {
        const body = await request.json();
        return json(await lc.rotateKey({ body, caller, idempotency_key }));
      }
      if (subpath === '/revoke') {
        const body = await request.json();
        return json(await lc.revoke({ body, caller, idempotency_key }));
      }
      return json(await lc.listKeys({ caller }));
    }

    throw error(404, { message: `unknown path: ${subpath}` });
  } catch (err) {
    const e = err as { status?: number; code?: string; message?: string };
    if (typeof e.status === 'number' && e.status >= 400 && e.status < 600) {
      return new Response(
        JSON.stringify({ error: { code: e.code ?? 'invalid_request', message: e.message } }),
        { status: e.status, headers: { 'content-type': 'application/json' } },
      );
    }
    throw err;
  }
};

export const GET = handler;
export const POST = handler;
