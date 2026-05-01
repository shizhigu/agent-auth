# OpenTelemetry tracing

Vouch ships an opt-in OTel-compatible tracing wrapper. The lib never imports `@opentelemetry/api` directly — you pass in a Tracer instance from your app's existing OTel SDK setup, and Vouch wraps each `auth.lifecycle.*` call in a span.

## Why this design

- **Zero overhead when off** — leave `tracing` undefined (the default) and no spans are created.
- **Bring your own tracer** — your app already has `@opentelemetry/sdk-node` (or `@opentelemetry/sdk-trace-web` etc.) configured. Vouch reuses that, no duplicate exporters or processors.
- **Structurally typed** — Vouch's `VouchTracerLike` matches the relevant subset of OTel's `Tracer` API (`startActiveSpan`), so any current or future-compatible OTel SDK works.

## Wire it up

```ts
import { trace } from '@opentelemetry/api';
import { vouch } from '@vouch/server';

const auth = await vouch({
  // ... database / redis / kms / identity / internal_secret ...
  tracing: {
    tracer: trace.getTracer('vouch'),
    service_name: 'my-saas',         // optional, used for default_attributes
  },
});
```

Once wired, every call to `auth.lifecycle.*` opens a span:

```
vouch.lifecycle.beginRegistration       — ~5 ms
vouch.lifecycle.callback                — ~25 ms
vouch.lifecycle.registrationStatus      — ~1 ms
vouch.lifecycle.rotateKey               — ~15 ms
vouch.lifecycle.revoke                  — ~10 ms
vouch.lifecycle.webhook                 — ~8 ms
vouch.lifecycle.validateBearer          — ~3 µs (cache hit) / ~6 µs (miss)
…
```

`wellKnown` is sync + pure (no I/O), so the wrapper skips it — instrumenting it would add overhead with no signal.

## Span attributes

Every span carries:

| Attribute | When |
|---|---|
| `vouch.method` | always (the lifecycle method name) |
| `vouch.provider` | begin / callback / webhook |
| `vouch.intent` | begin |
| `vouch.outcome` | callback / status / webhook (`success` / `failed` / `pending`) |
| `vouch.account_id` | callback (success), rotateKey, revoke, listKeys, validateBearer |
| `vouch.key_id` | validateBearer |
| `vouch.old_key_id` | rotateKey (the key being rotated away) |
| `vouch.tier` | validateBearer (cold/warm/hot) |
| `vouch.poll_token_kind` | registrationStatus (`pak_`, `pkr_`, `pad_`, `pav_`) |
| `vouch.label` | begin (the human label attached to the registration) |
| `http.status_code` | healthz |

## Errors

When a lifecycle method throws:

- The exception is recorded on the span via `span.recordException(err)`.
- The span status is set to `ERROR` with the error's message.
- The error is re-thrown unchanged — instrumentation is purely observational.

## Custom default attributes

Tag every Vouch span with the same metadata (deploy region, service name, etc.):

```ts
tracing: {
  tracer: trace.getTracer('vouch'),
  default_attributes: {
    'service.name': 'my-saas',
    'deploy.region': 'us-east-1',
    'deploy.env': process.env.NODE_ENV ?? 'dev',
  },
},
```

## Without OTel set up?

If you haven't initialized an OTel SDK, just leave `tracing` out:

```ts
const auth = await vouch({
  // no `tracing` field
});
```

The lib's `auth.lifecycle.*` calls are passthrough — zero overhead, no instrumentation.

## Direct use

If you want to instrument an already-built lifecycle (e.g. you constructed it manually or you're decorating a custom adapter), use the named helper:

```ts
import { instrumentLifecycle } from '@vouch/server';

const wrapped = instrumentLifecycle(auth.lifecycle, {
  tracer: trace.getTracer('vouch'),
});
```

## Companion observability

Vouch's other observability layers — see [SPEC §7](https://github.com/shizhigu/agent-auth/blob/main/SPEC.md) — work alongside tracing:

- **Prometheus metrics** — `MetricsRegistry` (counters, gauges, histograms with label scrubbing for RT-44).
- **Structured logs** — `createLogger()` with field scrubbing for sensitive values.

Wire all three for a full picture: traces tell you "what called what", metrics tell you "how often + how slow", logs tell you "what specifically happened on this request".
