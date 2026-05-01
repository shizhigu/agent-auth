/**
 * Unit tests for the OTel tracing wrapper. Uses a recording stub tracer
 * (no @opentelemetry/api dep) and a stub VouchLifecycle to exercise the
 * span-attribute logic without spinning up the full lib.
 */
import { describe, it, expect } from 'vitest';
import {
  instrumentLifecycle,
  SPAN_STATUS,
  type VouchSpanLike,
  type VouchTracerLike,
} from '../../src/observability/tracing.js';
import type { VouchLifecycle } from '../../src/factory.js';

interface RecordedSpan {
  name: string;
  attributes: Record<string, string | number | boolean>;
  status: { code: number; message?: string } | null;
  exceptions: unknown[];
  ended: boolean;
}

function recordingTracer(): { tracer: VouchTracerLike; spans: RecordedSpan[] } {
  const spans: RecordedSpan[] = [];

  const tracer: VouchTracerLike = {
    startActiveSpan: (
      name: string,
      optsOrFn: unknown,
      maybeFn?: unknown,
    ) => {
      const opts = typeof optsOrFn === 'function' ? undefined : (optsOrFn as { attributes?: Record<string, string | number | boolean> });
      const fn = (maybeFn ?? optsOrFn) as (span: VouchSpanLike) => unknown;
      const recorded: RecordedSpan = {
        name,
        attributes: { ...(opts?.attributes ?? {}) },
        status: null,
        exceptions: [],
        ended: false,
      };
      spans.push(recorded);
      const span: VouchSpanLike = {
        setAttribute(k, v) {
          recorded.attributes[k] = v;
        },
        setStatus(s) {
          recorded.status = s;
        },
        recordException(e) {
          recorded.exceptions.push(e);
        },
        end() {
          recorded.ended = true;
        },
      };
      return fn(span);
    },
  };

  return { tracer, spans };
}

function stubLifecycle(): VouchLifecycle {
  return {
    beginRegistration: async () => ({ poll_token: 'pak_x', challenge_url: 'u' }) as never,
    callback: async () => ({ status: 'success' as const, account_id: 'acc-1' }) as never,
    registrationStatus: async () => ({ status: 'pending' as const }) as never,
    recoverAccount: async () => ({ poll_token: 'pkr_x' }) as never,
    recoverAccountConfirm: async () => ({ decision: 'approved' as const }) as never,
    recoverAccountStatus: async () => ({ status: 'pending' as const }) as never,
    rotateKey: async () => ({ rotated: true }) as never,
    revoke: async () => ({ revoked: true }) as never,
    listKeys: async () => ({ keys: [] }) as never,
    webhook: async () => ({ status: 'processed' as const }) as never,
    healthz: async () => ({ http_status: 200, body: { status: 'healthy' } }) as never,
    wellKnown: () => ({ version: 'v1' }) as never,
    validateBearer: async () =>
      ({
        account_id: 'acc-1',
        key_id: 'k_1',
        tier: 'cold',
        identity: { provider: 'p', subject: 's', assurance_level: 'medium' },
        scopes: ['read'],
        has_scope: () => true,
        require_scope: () => undefined,
      }) as never,
  };
}

describe('instrumentLifecycle()', () => {
  it('opens a span per lifecycle call with vouch.method attribute', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), { tracer });

    await lc.beginRegistration({
      body: { provider: 'github_app', intent: 'register', label: 'demo-laptop' },
      request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
    });

    expect(spans).toHaveLength(1);
    expect(spans[0]?.name).toBe('vouch.lifecycle.beginRegistration');
    expect(spans[0]?.attributes['vouch.method']).toBe('beginRegistration');
    expect(spans[0]?.attributes['vouch.provider']).toBe('github_app');
    expect(spans[0]?.attributes['vouch.intent']).toBe('register');
    expect(spans[0]?.attributes['vouch.label']).toBe('demo-laptop');
    expect(spans[0]?.status?.code).toBe(SPAN_STATUS.OK);
    expect(spans[0]?.ended).toBe(true);
  });

  it('captures account_id + outcome on callback', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), { tracer });

    await lc.callback({
      input: { provider: 'github_app', state: 'x', code: 'y' },
      request_context: { ip_hash: Buffer.alloc(32), user_agent: 'test' },
    });

    expect(spans[0]?.attributes['vouch.provider']).toBe('github_app');
    expect(spans[0]?.attributes['vouch.outcome']).toBe('success');
    expect(spans[0]?.attributes['vouch.account_id']).toBe('acc-1');
  });

  it('records exceptions and sets ERROR status on throw', async () => {
    const { tracer, spans } = recordingTracer();
    const failing: VouchLifecycle = {
      ...stubLifecycle(),
      validateBearer: async () => {
        throw new Error('expired');
      },
    };
    const lc = instrumentLifecycle(failing, { tracer });

    await expect(lc.validateBearer('pak_bad')).rejects.toThrow('expired');

    expect(spans[0]?.status?.code).toBe(SPAN_STATUS.ERROR);
    expect(spans[0]?.status?.message).toBe('expired');
    expect(spans[0]?.exceptions).toHaveLength(1);
    expect((spans[0]?.exceptions[0] as Error).message).toBe('expired');
    expect(spans[0]?.ended).toBe(true);
  });

  it('honors span_name_prefix override', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), {
      tracer,
      span_name_prefix: 'auth.',
    });
    await lc.healthz();
    expect(spans[0]?.name).toBe('auth.healthz');
  });

  it('merges default_attributes onto every span', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), {
      tracer,
      default_attributes: { 'service.name': 'my-saas', 'deploy.region': 'us-east-1' },
    });
    await lc.healthz();
    expect(spans[0]?.attributes['service.name']).toBe('my-saas');
    expect(spans[0]?.attributes['deploy.region']).toBe('us-east-1');
  });

  it('tags rotateKey / revoke / listKeys with caller account_id', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), { tracer });
    const caller = {
      account_id: 'acc-42',
      key_id: 'k-old',
      tier: 'cold' as const,
      identity: { provider: 'p', subject: 's', assurance_level: 'medium' as const },
      scopes: [],
      has_scope: () => true,
      require_scope: () => undefined,
    };
    await lc.rotateKey({ body: {}, caller, idempotency_key: 'idem-1' });
    expect(spans[0]?.attributes['vouch.account_id']).toBe('acc-42');
    expect(spans[0]?.attributes['vouch.old_key_id']).toBe('k-old');
  });

  it('captures key_id + tier on validateBearer', async () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), { tracer });
    await lc.validateBearer('pak_x');
    expect(spans[0]?.attributes['vouch.account_id']).toBe('acc-1');
    expect(spans[0]?.attributes['vouch.key_id']).toBe('k_1');
    expect(spans[0]?.attributes['vouch.tier']).toBe('cold');
  });

  it('does NOT instrument wellKnown (sync, pure — would just add overhead)', () => {
    const { tracer, spans } = recordingTracer();
    const lc = instrumentLifecycle(stubLifecycle(), { tracer });
    lc.wellKnown({ base_url: 'https://x' });
    expect(spans).toHaveLength(0);
  });

  it('still ends the span when an exception is thrown', async () => {
    const { tracer, spans } = recordingTracer();
    const failing: VouchLifecycle = {
      ...stubLifecycle(),
      callback: async () => {
        throw new Error('boom');
      },
    };
    const lc = instrumentLifecycle(failing, { tracer });
    await expect(
      lc.callback({
        input: { provider: 'github_app', state: 's', code: 'c' },
        request_context: { ip_hash: Buffer.alloc(32), user_agent: 't' },
      }),
    ).rejects.toThrow();
    expect(spans[0]?.ended).toBe(true);
  });
});
