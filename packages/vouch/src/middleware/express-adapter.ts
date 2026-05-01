/**
 * Express adapter — wraps validateKey() as `app.use(agents.middleware())`.
 *
 * SPEC §6.3: the middleware sets `req.agent` (NEVER `req.user`). A SaaS
 * route handler reads `req.agent.account_id` to scope its DB queries
 * (RT-9 prevention). The lib augments the Express Request type so callers
 * see `req.agent` typed.
 *
 * SPEC §10.5: every authenticated response MUST include an `X-Request-Id`
 * header. If the inbound request did not provide one, the lib generates
 * a UUID v4 and echoes it on the response (so the client can quote it
 * back during incident response).
 *
 * Error mapping (§10.3): an AgentAuthError becomes
 *   { error: { code, message, request_id, documentation_url? } }
 * with the configured status. Any error.headers (Retry-After,
 * WWW-Authenticate, etc.) are copied through.
 *
 * The lib does NOT install body-parsing or CORS middleware. The SaaS owns
 * those. We only consume the Authorization header.
 */

import { randomUUID } from 'node:crypto';
import { AgentAuthError, isAgentAuthError } from '../errors.js';
import type { ValidateKeyDeps } from './validate-key.js';
import { validateKey } from './validate-key.js';
import type { AgentContext } from '../types.js';

export interface ExpressMiddlewareOptions {
  /** Where to read the bearer token from. Default: 'authorization' header. */
  readonly header?: string;
  /** Documentation URL base (errors get `${docs_url_base}#${code}`). */
  readonly docs_url_base?: string;
  /** Hook called on validation failure. Use it for metrics/logging. */
  readonly onReject?: (err: AgentAuthError, request_id: string) => void;
  /** Hook called on validation success. Use it for metrics/logging. */
  readonly onAccept?: (ctx: AgentContext, request_id: string) => void;
}

/**
 * Minimal subset of Express types we need. We do not import 'express'
 * because it is a peer dep — the SaaS provides it.
 */
interface ExpressLikeRequest {
  headers: { [key: string]: string | string[] | undefined };
  agent?: AgentContext;
}
interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  setHeader(name: string, value: string): void;
  json(body: unknown): unknown;
  headersSent: boolean;
}
type NextFunction = (err?: unknown) => void;

export type ExpressAgentMiddleware = (
  req: ExpressLikeRequest,
  res: ExpressLikeResponse,
  next: NextFunction,
) => void | Promise<void>;

const REQUEST_ID_HEADER = 'x-request-id';

function readHeader(
  headers: ExpressLikeRequest['headers'],
  name: string,
): string | undefined {
  const v = headers[name.toLowerCase()];
  if (Array.isArray(v)) return v[0];
  return v;
}

function extractBearer(auth: string | undefined): string | null {
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/i.exec(auth);
  if (!m) return null;
  return m[1]?.trim() ?? null;
}

/**
 * Build the Express middleware. Caller supplies the `ValidateKeyDeps`
 * (built once via `makeValidateKeyDeps(cfg)`). The returned function
 * is reusable and stateless — keep it as a singleton across requests.
 */
export function expressMiddleware(
  deps: ValidateKeyDeps,
  options: ExpressMiddlewareOptions = {},
): ExpressAgentMiddleware {
  const headerName = (options.header ?? 'authorization').toLowerCase();
  const docs_url_base = options.docs_url_base;

  return async function agentAuthMiddleware(req, res, next) {
    const inboundId = readHeader(req.headers, REQUEST_ID_HEADER);
    const request_id = inboundId ?? randomUUID();
    res.setHeader('X-Request-Id', request_id);

    try {
      const presented = extractBearer(readHeader(req.headers, headerName));
      if (!presented) {
        throw new AgentAuthError(401, 'invalid_key');
      }
      const ctx = await validateKey(presented, deps);
      req.agent = ctx;
      options.onAccept?.(ctx, request_id);
      next();
    } catch (err) {
      const e = isAgentAuthError(err)
        ? err
        : new AgentAuthError(500, 'internal_error', undefined, { cause: err });
      options.onReject?.(e, request_id);
      sendError(res, e, request_id, docs_url_base);
    }
  };
}

export function sendError(
  res: ExpressLikeResponse,
  err: AgentAuthError,
  request_id: string,
  docs_url_base?: string,
): void {
  if (res.headersSent) return; // race / double-write — let original response stand
  if (err.headers) {
    for (const [k, v] of Object.entries(err.headers)) {
      res.setHeader(k, v);
    }
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  const payload: {
    error: {
      code: string;
      message: string;
      request_id: string;
      documentation_url?: string;
      details?: Readonly<Record<string, unknown>>;
    };
  } = {
    error: {
      code: err.code,
      message: err.message || err.code,
      request_id,
    },
  };
  if (err.documentation_url) payload.error.documentation_url = err.documentation_url;
  else if (docs_url_base) payload.error.documentation_url = `${docs_url_base}#${err.code}`;
  if (err.details) payload.error.details = err.details;
  res.status(err.status).json(payload);
}

/**
 * Type augmentation: declare module 'express' is intentionally NOT done
 * here so the lib does not break SaaS apps that have already augmented
 * the Express namespace. Consumers who want the type should write:
 *
 *   declare module 'express' {
 *     interface Request { agent?: import('agent-auth').AgentContext }
 *   }
 *
 * We export the suggested augmentation as a doc fragment in README.md.
 * SPEC §6.3 emphasizes that req.user is NEVER extended by the lib.
 */
