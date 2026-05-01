/**
 * vouch() — high-level factory that takes a flat, JSON-serializable config
 * and returns a ready-to-mount auth instance.
 *
 * Designed to make the SaaS-side quick start fit on one screen instead of
 * requiring 60 lines of adapter wiring. The factory is sugar on top of the
 * existing primitives — power users can still construct PostgresAdapter /
 * IoredisAdapter / AwsKmsAdapter / GitHubAppProvider manually and use the
 * lib's lower-level API; nothing here is a replacement.
 *
 * What the factory does for you:
 *
 *   - Builds Postgres / Redis / KMS adapters from urls + config (no manual
 *     `new Pool({...})` / `new Redis({...})` / `new KMSClient({...})`).
 *   - Runs lib startup: `redis.loadScripts()` + `sealedBoxReady()`.
 *   - Wires the 12 lifecycle routes (begin-registration, callback,
 *     registration-status, rotate-key, revoke, recover-account*,
 *     webhooks/:provider, healthz, well-known, list-keys) behind a single
 *     Express RequestHandler.
 *   - Auto-handles raw-body parsing for webhook signature verification
 *     while parsing JSON for the other lifecycle routes.
 *   - Wires the validate-key middleware for protected API routes.
 *   - Exposes the underlying adapters and resolved config for power users.
 *
 * What it does NOT do:
 *
 *   - npm publish, dashboard UI, multi-tenant control plane, SAML —
 *     those are Vouch Cloud features (v1.0).
 *   - Multiple identity providers in a single instance — currently the
 *     factory only wires up GitHub. Generic OIDC + Google providers ship
 *     in v0.3.
 */

import type { PoolConfig } from 'pg';
import type { Redis as IoRedis, RedisOptions } from 'ioredis';
import type { Request, Response, NextFunction, RequestHandler, Express } from 'express';
import Redis from 'ioredis';
import express from 'express';
import { KMSClient } from '@aws-sdk/client-kms';
import { createHash } from 'node:crypto';

import { PostgresAdapter } from './storage/postgres-adapter.js';
import { IoredisAdapter } from './storage/redis-adapter.js';
import {
  AwsKmsAdapter,
  InMemoryKmsAdapter,
  type KmsAdapter,
} from './storage/kms-adapter.js';
import {
  GitHubAppProvider,
  type GitHubAppProviderConfig,
} from './identity/github-app/browser-flow.js';
import {
  resolveConfig,
  type ResolvedConfig,
  type ValidationConfig,
  type RateLimitConfig,
  type AuditLogConfig,
  type MultiRegionConfig,
  type ObservabilityConfig,
  type RecoverAccountConfig,
  type ReconciliationConfig,
  type RevalidationConfig,
  type FailoverConfig,
} from './config.js';
import { sealedBoxReady } from './crypto/sealed-box.js';
import { makeValidateKeyDeps } from './middleware/validate-key.js';
import {
  expressMiddleware,
  type ExpressMiddlewareOptions,
} from './middleware/express-adapter.js';
import { beginRegistration } from './routes/begin-registration.js';
import { callback as routeCallback } from './routes/callback.js';
import { registrationStatus } from './routes/registration-status.js';
import { rotateKey } from './routes/rotate-key.js';
import { revoke } from './routes/revoke.js';
import { recoverAccount } from './routes/recover-account.js';
import { recoverAccountConfirm } from './routes/recover-account-confirm.js';
import { recoverAccountStatus } from './routes/recover-account-status.js';
import { handleWebhookRequest } from './routes/webhooks.js';
import { healthz } from './routes/healthz.js';
import { wellKnown } from './routes/well-known.js';
import { listKeys } from './routes/list-keys.js';
import type { AgentContext, IdentityProvider } from './types.js';
import { AgentAuthError } from './errors.js';

// ---------------------------------------------------------------------------
// Public config — flat, JSON-friendly
// ---------------------------------------------------------------------------

export type DatabaseInit =
  | { readonly url: string }
  | { readonly config: PoolConfig };

export type RedisInit =
  | { readonly url: string }
  | { readonly options: RedisOptions }
  | { readonly client: IoRedis; readonly subscriber: IoRedis };

export interface AwsKmsInit {
  readonly provider: 'aws';
  readonly region: string;
  readonly pepper_alias: string;
  readonly device_alias: string;
  readonly pepperFetcher: (version: number) => Promise<Buffer>;
  readonly current_version?: number;
}

export interface InMemoryKmsInit {
  readonly provider: 'in-memory';
  readonly pepper?: Buffer;
  readonly initial_version?: number;
}

export type KmsInit = AwsKmsInit | InMemoryKmsInit;

export interface IdentityInit {
  readonly github?: GitHubAppProviderConfig;
  /**
   * Pre-built provider instances. Use this for in-house providers, generic
   * OIDC, SAML wrappers, or test stubs that don't have a built-in shortcut
   * here. Providers added via `custom` run alongside any declared shortcuts
   * (e.g. `github` + a custom OIDC).
   */
  readonly custom?: ReadonlyArray<IdentityProvider>;
}

export interface VouchInit {
  readonly database: DatabaseInit;
  readonly redis: RedisInit;
  readonly kms: KmsInit;
  readonly identity: IdentityInit;
  /** 32-byte secret as base64 string OR raw Buffer. */
  readonly internal_secret: string | Buffer;
  /** Public URL of your SaaS, e.g. `https://api.acme.com`. Used to compute the default redirect_uri. */
  readonly base_url?: string;
  /** Mount path for lifecycle routes. Default `/agent-auth`. */
  readonly mount_path?: string;
  /** Region (defaults to AWS region for `kms.provider='aws'`, otherwise `local`). */
  readonly region?: string;
  /** Override per-provider audience. Defaults to provider name. */
  readonly audience?: string | ((provider: string) => string);
  /** Override per-provider redirect URI. Defaults to `${base_url}${mount_path}/callback`. */
  readonly redirect_uri?: string | ((provider: string) => string);
  /** Optional logger / alert hook for webhook collisions etc. */
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
  // Pass-through to ResolvedConfig for power users
  readonly validation?: ValidationConfig;
  readonly rate_limit?: RateLimitConfig;
  readonly audit_log?: AuditLogConfig;
  readonly multi_region?: MultiRegionConfig;
  readonly observability?: ObservabilityConfig;
  readonly recover_account?: RecoverAccountConfig;
  readonly reconciliation?: ReconciliationConfig;
  readonly revalidation?: RevalidationConfig;
  readonly failover?: FailoverConfig;
}

// ---------------------------------------------------------------------------
// VouchInstance — what the factory returns
// ---------------------------------------------------------------------------

export interface VouchExpress {
  /**
   * Mount Vouch on an Express app. Wires body parsing + dispatcher in one
   * call. **Call this BEFORE** any global `express.json()` so webhook
   * raw-body handling stays intact.
   */
  mount(app: Express, opts?: { mount_path?: string }): void;
  /**
   * Lower-level: a single RequestHandler that dispatches all lifecycle
   * routes. Use if you want to control body parsing yourself; otherwise
   * prefer `mount()`.
   */
  handler(opts?: { mount_path?: string }): RequestHandler;
  /**
   * Validate-key middleware. Mount on protected API routes
   * (e.g. `app.use('/api/agent/v1', auth.express.middleware())`). Sets
   * `req.agent: AgentContext` per SPEC §6.3 (NOT `req.user`).
   */
  middleware(opts?: ExpressMiddlewareOptions): RequestHandler;
}

export interface VouchInstance {
  readonly config: ResolvedConfig;
  readonly adapters: {
    readonly postgres: PostgresAdapter;
    readonly redis: IoredisAdapter;
    readonly kms: KmsAdapter;
  };
  readonly express: VouchExpress;
  shutdown(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export async function vouch(init: VouchInit): Promise<VouchInstance> {
  // -------- Synchronous validation FIRST so misconfig fails fast --------
  // (Important: don't try to connect to Redis / KMS until config is valid.)
  const internal_secret = coerceBuffer32(init.internal_secret, 'internal_secret');

  const identity_providers: IdentityProvider[] = [];
  if (init.identity.github) {
    identity_providers.push(new GitHubAppProvider(init.identity.github));
  }
  if (init.identity.custom) {
    identity_providers.push(...init.identity.custom);
  }
  if (identity_providers.length === 0) {
    throw new Error(
      'vouch(): identity must include at least one provider (e.g. identity.github or identity.custom)',
    );
  }

  // -------- Build adapters --------
  const pgConfig: PoolConfig =
    'config' in init.database ? init.database.config : { connectionString: init.database.url };
  const postgres = new PostgresAdapter({ pool: pgConfig, role: 'agent_auth_app' });

  const { client: redisClient, subscriber: redisSub, owned: ownsRedis } = buildRedisClients(init.redis);
  const redis = new IoredisAdapter({ client: redisClient, subscriber: redisSub });
  await redis.loadScripts();

  const kms = buildKms(init.kms);
  await sealedBoxReady();

  // 4. Resolve config
  const config = resolveConfig({
    internal_secret,
    identity_providers,
    storage: { postgres, redis, kms },
    ...(init.validation !== undefined ? { validation: init.validation } : {}),
    ...(init.rate_limit !== undefined ? { rate_limit: init.rate_limit } : {}),
    ...(init.audit_log !== undefined ? { audit_log: init.audit_log } : {}),
    ...(init.multi_region !== undefined ? { multi_region: init.multi_region } : {}),
    ...(init.observability !== undefined ? { observability: init.observability } : {}),
    ...(init.recover_account !== undefined ? { recover_account: init.recover_account } : {}),
    ...(init.reconciliation !== undefined ? { reconciliation: init.reconciliation } : {}),
    ...(init.revalidation !== undefined ? { revalidation: init.revalidation } : {}),
    ...(init.failover !== undefined ? { failover: init.failover } : {}),
  });

  // 5. Compute mount_path / audience / redirect_uri / region
  const mount_path = normalizePath(init.mount_path ?? '/agent-auth');
  const region =
    init.region ??
    (init.kms.provider === 'aws' ? init.kms.region : 'local');
  const audience: (p: string) => string = (provider) => {
    if (typeof init.audience === 'function') return init.audience(provider);
    if (typeof init.audience === 'string') return init.audience;
    return provider;
  };
  const redirect_uri: (p: string) => string = (provider) => {
    if (typeof init.redirect_uri === 'function') return init.redirect_uri(provider);
    if (typeof init.redirect_uri === 'string') return init.redirect_uri;
    if (init.base_url) return `${trimTrailingSlash(init.base_url)}${mount_path}/callback`;
    return `${mount_path}/callback`;
  };

  // 6. Validate-key deps (used by middleware AND by protected routes inside dispatcher)
  const validateDeps = makeValidateKeyDeps(config);

  const dispatcherDeps: DispatcherDeps = {
    mount_path,
    base_url: trimTrailingSlash(init.base_url ?? ''),
    postgres,
    redis,
    kms,
    identity_providers,
    audience,
    redirect_uri,
    region,
    onAlert: init.onAlert ?? (() => {}),
    validateDeps,
    internal_secret,
    validation_mode: config.validation.mode,
  };

  const expressApi: VouchExpress = {
    mount(app, opts) {
      const path = normalizePath(opts?.mount_path ?? mount_path);
      // 1. Webhooks need raw-body for signature verification.
      app.use(`${path}/webhooks`, express.raw({ type: '*/*', limit: '512kb' }));
      // 2. Other lifecycle routes parse JSON.
      app.use(path, express.json({ limit: '4kb' }));
      // 3. Single dispatcher for all sub-paths.
      app.all(`${path}/*`, makeExpressHandler({ ...dispatcherDeps, mount_path: path }));
    },
    handler(opts) {
      const path = normalizePath(opts?.mount_path ?? mount_path);
      return makeExpressHandler({ ...dispatcherDeps, mount_path: path });
    },
    middleware(opts) {
      return expressMiddleware(validateDeps, opts);
    },
  };

  return {
    config,
    adapters: { postgres, redis, kms },
    express: expressApi,
    async shutdown() {
      await postgres.close().catch(() => undefined);
      await redis.close?.().catch(() => undefined);
      if (ownsRedis) {
        redisClient.disconnect();
        redisSub.disconnect();
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Dispatcher — single Express handler that routes lifecycle paths
// ---------------------------------------------------------------------------

interface DispatcherDeps {
  mount_path: string;
  base_url: string;
  postgres: PostgresAdapter;
  redis: IoredisAdapter;
  kms: KmsAdapter;
  identity_providers: IdentityProvider[];
  audience: (provider: string) => string;
  redirect_uri: (provider: string) => string;
  region: string;
  onAlert: (label: string, meta: Record<string, unknown>) => void;
  validateDeps: ReturnType<typeof makeValidateKeyDeps>;
  internal_secret: Buffer;
  validation_mode: ResolvedConfig['validation']['mode'];
}

function makeExpressHandler(d: DispatcherDeps): RequestHandler {
  const middleware = expressMiddleware(d.validateDeps);
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.path.startsWith(d.mount_path)) return next();
    const subpath = req.path.slice(d.mount_path.length) || '/';
    const ctx = requestContext(req);

    try {
      // ---------- Public lifecycle ----------
      if (subpath === '/begin-registration' && req.method === 'POST') {
        const out = await beginRegistration(req.body, {
          postgres: d.postgres,
          identity_providers: d.identity_providers,
          redirect_uri: d.redirect_uri,
          audience: d.audience,
          request_context: ctx,
        });
        return void res.json(out);
      }
      if (subpath === '/callback' && req.method === 'GET') {
        const provider =
          (typeof req.query.provider === 'string' ? req.query.provider : undefined) ??
          d.identity_providers[0]?.name ??
          '';
        const callbackInput: Parameters<typeof routeCallback>[0] = {
          provider,
          state: String(req.query.state ?? ''),
          code: String(req.query.code ?? ''),
        };
        if (typeof req.query.error === 'string') {
          (callbackInput as { error?: string }).error = req.query.error;
        }
        if (typeof req.query.error_description === 'string') {
          (callbackInput as { error_description?: string }).error_description = req.query.error_description;
        }
        const out = await routeCallback(callbackInput, {
          postgres: d.postgres,
          kms: d.kms,
          identity_providers: d.identity_providers,
          request_context: ctx,
        });
        return void res.json(out);
      }
      if (subpath === '/registration-status' && req.method === 'GET') {
        const out = await registrationStatus(
          { poll_token: String(req.query.poll_token ?? '') },
          { postgres: d.postgres, endpoint: 'registration' },
        );
        return void res.json(out);
      }
      if (subpath === '/recover-account' && req.method === 'POST') {
        const out = await recoverAccount(req.body, {
          postgres: d.postgres,
          identity_providers: d.identity_providers,
          redirect_uri: d.redirect_uri,
          audience: d.audience,
          request_context: ctx,
        });
        return void res.json(out);
      }
      if (subpath === '/recover-account-confirm' && req.method === 'POST') {
        const out = await recoverAccountConfirm(req.body, {
          postgres: d.postgres,
          redis: d.redis,
          internal_secret: d.internal_secret,
          kms: d.kms,
        });
        return void res.json(out);
      }
      if (subpath === '/recover-account-status' && req.method === 'GET') {
        const out = await recoverAccountStatus(
          { poll_token: String(req.query.poll_token ?? '') },
          { postgres: d.postgres },
        );
        return void res.json(out);
      }
      if (subpath === '/healthz' && req.method === 'GET') {
        const out = await healthz({ postgres: d.postgres, redis: d.redis });
        return void res.status(out.http_status).json(out.body);
      }
      if (subpath === '/well-known' && req.method === 'GET') {
        const out = wellKnown({
          base_url: d.base_url || `${req.protocol}://${req.get('host') ?? 'localhost'}`,
          identity_providers: d.identity_providers,
          barrier_mode: d.validation_mode,
        });
        return void res.json(out);
      }
      // ---------- Webhooks (raw body) ----------
      if (subpath.startsWith('/webhooks/') && req.method === 'POST') {
        const provider = subpath.slice('/webhooks/'.length);
        const body = req.body instanceof Buffer ? req.body : Buffer.from(req.body ?? '');
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          headers[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v ?? '');
        }
        const out = await handleWebhookRequest(
          { provider, headers, raw_body: body },
          {
            postgres: d.postgres,
            redis: d.redis,
            identity_providers: d.identity_providers,
            region: d.region,
            onAlert: d.onAlert,
          },
        );
        return void res.json(out);
      }
      // ---------- Authenticated agent-management ----------
      if (
        (subpath === '/rotate-key' && req.method === 'POST') ||
        (subpath === '/revoke' && req.method === 'POST') ||
        (subpath === '/list-keys' && req.method === 'GET')
      ) {
        // Run validate-key middleware to populate req.agent.
        const proceed = await runMiddleware(middleware, req, res);
        if (!proceed) return;
        const agent = (req as Request & { agent?: AgentContext }).agent;
        if (!agent) {
          throw new AgentAuthError(401, 'invalid_key');
        }
        if (subpath === '/rotate-key') {
          const idempotencyKey = String(req.headers['idempotency-key'] ?? '');
          const out = await rotateKey(req.body, {
            postgres: d.postgres,
            redis: d.redis,
            kms: d.kms,
            region: d.region,
            caller: agent,
            idempotency_key: idempotencyKey,
          });
          return void res.json(out);
        }
        if (subpath === '/revoke') {
          const idempotencyKey = String(req.headers['idempotency-key'] ?? '');
          const out = await revoke(req.body, {
            postgres: d.postgres,
            redis: d.redis,
            region: d.region,
            caller: agent,
            idempotency_key: idempotencyKey,
          });
          return void res.json(out);
        }
        if (subpath === '/list-keys') {
          const out = await listKeys({ postgres: d.postgres, caller: agent });
          return void res.json(out);
        }
      }
      // No match — pass through.
      return next();
    } catch (e) {
      next(e);
    }
  };
}

// Run an Express middleware as a one-shot async function — resolves to true
// if `next()` was called (i.e., proceed), false if the middleware ended the
// response itself (e.g., 401 from validate-key).
function runMiddleware(
  mw: RequestHandler,
  req: Request,
  res: Response,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    let settled = false;
    res.once('finish', () => {
      if (!settled) {
        settled = true;
        resolve(false);
      }
    });
    Promise.resolve(
      mw(req, res, (err?: unknown) => {
        if (settled) return;
        settled = true;
        if (err) reject(err);
        else resolve(true);
      }),
    ).catch((err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Internals — adapter builders + helpers
// ---------------------------------------------------------------------------

function buildRedisClients(r: RedisInit): {
  client: IoRedis;
  subscriber: IoRedis;
  owned: boolean;
} {
  if ('client' in r && 'subscriber' in r) {
    return { client: r.client, subscriber: r.subscriber, owned: false };
  }
  if ('options' in r) {
    const c = new Redis(r.options);
    return { client: c, subscriber: c.duplicate(), owned: true };
  }
  const c = new Redis(r.url);
  return { client: c, subscriber: c.duplicate(), owned: true };
}

function buildKms(k: KmsInit): KmsAdapter {
  if (k.provider === 'aws') {
    return new AwsKmsAdapter({
      client: new KMSClient({ region: k.region }),
      pepper_key_alias: k.pepper_alias,
      device_key_alias: k.device_alias,
      current_version: k.current_version ?? 1,
      pepperFetcher: k.pepperFetcher,
    });
  }
  return new InMemoryKmsAdapter({
    ...(k.pepper !== undefined ? { initial_pepper: k.pepper } : {}),
    ...(k.initial_version !== undefined ? { initial_version: k.initial_version } : {}),
  });
}

function coerceBuffer32(v: string | Buffer, label: string): Buffer {
  const buf = typeof v === 'string' ? Buffer.from(v, 'base64') : v;
  if (buf.length !== 32) {
    throw new Error(`vouch(): ${label} must be 32 bytes (got ${buf.length})`);
  }
  return buf;
}

function normalizePath(p: string): string {
  let s = p.startsWith('/') ? p : `/${p}`;
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return s;
}

function trimTrailingSlash(s: string): string {
  return s.endsWith('/') ? s.slice(0, -1) : s;
}

function requestContext(req: Request) {
  const ip = req.ip ?? '127.0.0.1';
  const ip_hash = createHash('sha256').update(ip).digest();
  const user_agent = String(req.headers['user-agent'] ?? '');
  return { ip_hash, user_agent };
}
