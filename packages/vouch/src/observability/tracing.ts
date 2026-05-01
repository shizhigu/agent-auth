/**
 * OpenTelemetry tracing — opt-in, no runtime dep on @opentelemetry/api.
 *
 * Vouch never imports `@opentelemetry/api` directly. Instead, the SaaS
 * passes an OTel-compatible `Tracer` instance via `tracing.tracer`, and
 * the lib wraps each `auth.lifecycle.*` call in a span. This:
 *
 *   - Keeps `agent-auth` runtime-clean: no peer dep on OTel.
 *   - Lets users opt out by simply not passing `tracing` (zero overhead).
 *   - Stays compatible with future OTel API revisions: we depend only on
 *     the four span methods we actually call (setAttribute, setStatus,
 *     recordException, end) and `tracer.startActiveSpan()`.
 *
 * Usage from a SaaS that already has OTel set up:
 *
 *   import { trace } from '@opentelemetry/api';
 *
 *   const auth = await vouch({
 *     // ...
 *     tracing: { tracer: trace.getTracer('my-saas'), service_name: 'my-saas' },
 *   });
 *
 * Each lifecycle call now opens a span named `vouch.lifecycle.<method>`,
 * with attributes:
 *   - vouch.method            (begin_registration, callback, …)
 *   - vouch.outcome           (success | failed | pending)
 *   - vouch.account_id        (when known)
 *   - vouch.key_id            (when known)
 *   - vouch.provider          (when known)
 *   - exception.*             (on throw, via recordException)
 */

import type { VouchLifecycle } from '../factory.js';

// ---------------------------------------------------------------------------
// Structural OTel types — match @opentelemetry/api's Tracer/Span shapes so
// `trace.getTracer(...)` can be passed in directly.
// ---------------------------------------------------------------------------

/** OTel SpanStatusCode — 0=UNSET, 1=OK, 2=ERROR. */
export const SPAN_STATUS = { UNSET: 0, OK: 1, ERROR: 2 } as const;
export type SpanStatusCode = (typeof SPAN_STATUS)[keyof typeof SPAN_STATUS];

export interface VouchSpanLike {
  setAttribute(key: string, value: string | number | boolean): void;
  setStatus(status: { code: SpanStatusCode; message?: string }): void;
  recordException(err: unknown): void;
  end(): void;
}

export interface VouchTracerLike {
  startActiveSpan<T>(name: string, fn: (span: VouchSpanLike) => T): T;
  startActiveSpan<T>(
    name: string,
    options: { attributes?: Record<string, string | number | boolean> },
    fn: (span: VouchSpanLike) => T,
  ): T;
}

// ---------------------------------------------------------------------------
// Public config
// ---------------------------------------------------------------------------

export interface TracingConfig {
  /** OTel-compatible Tracer. Pass `trace.getTracer('vouch')` from your app's OTel SDK. */
  readonly tracer: VouchTracerLike;
  /** Override the span name prefix. Default `vouch.lifecycle.`. */
  readonly span_name_prefix?: string;
  /** Add custom attributes to every span. */
  readonly default_attributes?: Readonly<Record<string, string | number | boolean>>;
}

// ---------------------------------------------------------------------------
// Instrumentation — wraps a VouchLifecycle so every method opens a span.
// ---------------------------------------------------------------------------

/**
 * Decorate a `VouchLifecycle` so each method call opens an OTel span. The
 * returned object is shape-identical to the input; only side effects differ.
 */
export function instrumentLifecycle(
  lifecycle: VouchLifecycle,
  cfg: TracingConfig,
): VouchLifecycle {
  const prefix = cfg.span_name_prefix ?? 'vouch.lifecycle.';
  const defaults = cfg.default_attributes ?? {};
  const tracer = cfg.tracer;

  // wrapAsync: for the 11 async lifecycle methods. `wellKnown` is sync and
  // pure (no I/O), so we don't instrument it — leaving it untouched keeps
  // the type signature unchanged.
  const wrapAsync = <Args extends unknown[], R>(
    method: keyof VouchLifecycle,
    fn: (...args: Args) => Promise<R>,
    enrich?: (args: Args, result: R) => Record<string, string | number | boolean>,
  ): ((...args: Args) => Promise<R>) => {
    return (...args: Args): Promise<R> => {
      const span_name = `${prefix}${String(method)}`;
      return tracer.startActiveSpan<Promise<R>>(
        span_name,
        { attributes: { 'vouch.method': String(method), ...defaults } },
        async (span) => {
          try {
            const result = await fn(...args);
            if (enrich) {
              const extra = enrich(args, result);
              for (const [k, v] of Object.entries(extra)) span.setAttribute(k, v);
            }
            span.setStatus({ code: SPAN_STATUS.OK });
            return result;
          } catch (err) {
            span.recordException(err);
            const message = (err as { message?: string })?.message ?? String(err);
            span.setStatus({ code: SPAN_STATUS.ERROR, message });
            throw err;
          } finally {
            span.end();
          }
        },
      );
    };
  };

  return {
    beginRegistration: wrapAsync(
      'beginRegistration',
      lifecycle.beginRegistration.bind(lifecycle),
      ([args]) => attrsFromBody(args.body),
    ),
    callback: wrapAsync(
      'callback',
      lifecycle.callback.bind(lifecycle),
      ([args], result) => ({
        'vouch.provider': args.input.provider,
        'vouch.outcome': (result as { status?: string }).status ?? 'unknown',
        ...((result as { account_id?: string }).account_id
          ? { 'vouch.account_id': (result as { account_id: string }).account_id }
          : {}),
      }),
    ),
    registrationStatus: wrapAsync(
      'registrationStatus',
      lifecycle.registrationStatus.bind(lifecycle),
      ([args], result) => ({
        'vouch.poll_token_kind': pollTokenPrefix(args.poll_token),
        'vouch.outcome': (result as { status?: string }).status ?? 'unknown',
      }),
    ),
    recoverAccount: wrapAsync(
      'recoverAccount',
      lifecycle.recoverAccount.bind(lifecycle),
      ([args]) => attrsFromBody(args.body),
    ),
    recoverAccountConfirm: wrapAsync(
      'recoverAccountConfirm',
      lifecycle.recoverAccountConfirm.bind(lifecycle),
      ([_args], result) => ({
        'vouch.outcome': (result as { decision?: string }).decision ?? 'unknown',
      }),
    ),
    recoverAccountStatus: wrapAsync(
      'recoverAccountStatus',
      lifecycle.recoverAccountStatus.bind(lifecycle),
      ([_args], result) => ({
        'vouch.outcome': (result as { status?: string }).status ?? 'unknown',
      }),
    ),
    rotateKey: wrapAsync(
      'rotateKey',
      lifecycle.rotateKey.bind(lifecycle),
      ([args]) => ({
        'vouch.account_id': args.caller.account_id,
        'vouch.old_key_id': args.caller.key_id,
      }),
    ),
    revoke: wrapAsync(
      'revoke',
      lifecycle.revoke.bind(lifecycle),
      ([args]) => ({ 'vouch.account_id': args.caller.account_id }),
    ),
    listKeys: wrapAsync(
      'listKeys',
      lifecycle.listKeys.bind(lifecycle),
      ([args]) => ({ 'vouch.account_id': args.caller.account_id }),
    ),
    webhook: wrapAsync(
      'webhook',
      lifecycle.webhook.bind(lifecycle),
      ([args], result) => ({
        'vouch.provider': args.provider,
        'vouch.outcome': (result as { status?: string }).status ?? 'unknown',
      }),
    ),
    healthz: wrapAsync(
      'healthz',
      lifecycle.healthz.bind(lifecycle),
      (_args, result) => ({
        'vouch.outcome': result.body.status,
        'http.status_code': result.http_status,
      }),
    ),
    // wellKnown is sync + pure; instrumenting it would add overhead for
    // no signal (no I/O happens in this method). Pass through unchanged.
    wellKnown: lifecycle.wellKnown.bind(lifecycle),
    validateBearer: wrapAsync(
      'validateBearer',
      lifecycle.validateBearer.bind(lifecycle),
      (_args, result) => ({
        'vouch.account_id': result.account_id,
        'vouch.key_id': result.key_id,
        'vouch.tier': result.tier,
      }),
    ),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function pollTokenPrefix(token: string): string {
  return token.slice(0, 4); // pak_, pkr_, pad_, pav_
}

function attrsFromBody(body: unknown): Record<string, string | number | boolean> {
  if (typeof body !== 'object' || body === null) return {};
  const b = body as { provider?: string; intent?: string; label?: string };
  const out: Record<string, string | number | boolean> = {};
  if (typeof b.provider === 'string') out['vouch.provider'] = b.provider;
  if (typeof b.intent === 'string') out['vouch.intent'] = b.intent;
  if (typeof b.label === 'string') out['vouch.label'] = b.label;
  return out;
}
