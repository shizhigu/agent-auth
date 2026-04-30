/**
 * Hono adapter — the Hono equivalent of the Express middleware.
 *
 * Hono passes a Context (`c`) instead of (req, res, next). The adapter:
 *   - reads Authorization (or configured header)
 *   - calls validateKey(deps)
 *   - sets c.set('agent', ctx) on success — consumers read via
 *     c.get('agent') (typed below via module augmentation guidance)
 *   - on AgentAuthError, returns a JSON Response with the SPEC §10.3 shape
 *
 * Like the Express adapter, this module does NOT depend on `hono` at
 * runtime. It uses a structural type for `Context` so the SaaS keeps
 * sole control of the `hono` peer dep.
 */

import { randomUUID } from 'node:crypto';
import { AgentAuthError, isAgentAuthError } from '../errors.js';
import type { ValidateKeyDeps } from './validate-key.js';
import { validateKey } from './validate-key.js';
import type { AgentContext } from '../types.js';

interface HonoLikeRequest {
  header(name: string): string | undefined;
}
export interface HonoLikeContext {
  req: HonoLikeRequest;
  set(key: 'agent', value: AgentContext): void;
  set(key: string, value: unknown): void;
  json(body: unknown, status?: number, headers?: Record<string, string>): Response;
  /** Hono v4 — sets a header on the outgoing response. Used to echo
   *  X-Request-Id on the success path per SPEC §10.5. */
  header(name: string, value: string): void;
}
type Next = () => Promise<void>;

export interface HonoMiddlewareOptions {
  readonly header?: string;
  readonly docs_url_base?: string;
  readonly onReject?: (err: AgentAuthError, request_id: string) => void;
  readonly onAccept?: (ctx: AgentContext, request_id: string) => void;
}

const REQUEST_ID_HEADER = 'x-request-id';

function extractBearer(auth: string | undefined): string | null {
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return null;
  return m[1]?.trim() ?? null;
}

export type HonoAgentMiddleware = (c: HonoLikeContext, next: Next) => Promise<Response | void>;

export function honoMiddleware(
  deps: ValidateKeyDeps,
  options: HonoMiddlewareOptions = {},
): HonoAgentMiddleware {
  const headerName = (options.header ?? 'authorization').toLowerCase();
  const docs_url_base = options.docs_url_base;

  return async function agentAuthMiddleware(c, next) {
    const inboundId = c.req.header(REQUEST_ID_HEADER);
    const request_id = inboundId ?? randomUUID();

    try {
      const presented = extractBearer(c.req.header(headerName));
      if (!presented) {
        throw new AgentAuthError(401, 'invalid_key');
      }
      const ctx = await validateKey(presented, deps);
      c.set('agent', ctx);
      options.onAccept?.(ctx, request_id);
      await next();
      // SPEC §10.5: every authenticated response MUST carry X-Request-Id.
      // Hono v4's `c.header(name, value)` mutates the outgoing response
      // headers regardless of whether the route handler set them. Set
      // AFTER next() so a downstream handler that explicitly overrode
      // the header still wins (defensive: it shouldn't, but if a SaaS
      // app does, we don't clobber).
      c.header('X-Request-Id', request_id);
      return;
    } catch (err) {
      const e = isAgentAuthError(err)
        ? err
        : new AgentAuthError(500, 'internal_error', undefined, { cause: err });
      options.onReject?.(e, request_id);
      const headers: Record<string, string> = { 'X-Request-Id': request_id };
      if (e.headers) Object.assign(headers, e.headers);
      const body: {
        error: {
          code: string;
          message: string;
          request_id: string;
          documentation_url?: string;
          details?: Readonly<Record<string, unknown>>;
        };
      } = {
        error: {
          code: e.code,
          message: e.message || e.code,
          request_id,
        },
      };
      if (e.documentation_url) body.error.documentation_url = e.documentation_url;
      else if (docs_url_base) body.error.documentation_url = `${docs_url_base}#${e.code}`;
      if (e.details) body.error.details = e.details;
      return c.json(body, e.status, headers);
    }
  };
}

/**
 * Suggested type augmentation for SaaS apps:
 *
 *   declare module 'hono' {
 *     interface ContextVariableMap {
 *       agent: import('agent-auth').AgentContext;
 *     }
 *   }
 *
 * After that, `c.get('agent')` is typed as AgentContext.
 */
