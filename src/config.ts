/**
 * AgentAuthConfig — top-level configuration the SaaS supplies when
 * initializing the lib. Mirrors SPEC §11.4. Defaults applied by
 * `resolveConfig()` are intentionally explicit (no hidden globals).
 */

import type { Clock, IdentityProvider } from './types.js';
import type { KmsAdapter } from './storage/kms-adapter.js';
import type { RedisAdapter } from './storage/redis-adapter.js';
import type { PostgresAdapter } from './storage/postgres-adapter.js';
import type { WormPutter } from './audit/worm-writer.js';

export type ValidationMode =
  /** Always read epoch from Redis on every validation (1 RTT). */
  | 'strict_uncached'
  /** Cache epoch in-process for up to `bounded_stale_ms`; refresh in background. */
  | { kind: 'bounded_stale'; bounded_stale_ms: number };

export interface ValidationConfig {
  /** Default 'strict_uncached' for highest consistency. */
  readonly mode?: ValidationMode;
  /** Local LRU capacity. Default 1000 (§5.3.1). */
  readonly local_cache_capacity?: number;
  /** Local LRU TTL ms. Default 30 000 (§5.3.1). */
  readonly local_cache_ttl_ms?: number;
  /** Redis cache TTL seconds. Default 30 (§5.3.1). */
  readonly redis_cache_ttl_seconds?: number;
}

export interface RateLimitDimension {
  readonly burst: number;
  /** Period in seconds. */
  readonly period: number;
}

export interface RateLimitConfig {
  readonly per_key?: RateLimitDimension;
  readonly per_account?: RateLimitDimension;
  readonly per_ip_registration?: RateLimitDimension;
  readonly global_emergency?: RateLimitDimension;
  readonly per_route_overrides?: Readonly<Record<string, { cost_units: number }>>;
  /** Default 'gcra'; the only supported algorithm in v0.1. */
  readonly algorithm?: 'gcra';
  /** Default 'redis'. */
  readonly storage?: 'redis';
}

export interface AuditLogConfig {
  /** S3 bucket for WORM audit copies. If unset, only in-DB chain runs. */
  readonly external_worm?: {
    readonly bucket: string;
    readonly aws_account: string;
    readonly region: string;
    readonly retention_years: number;
    /** 'COMPLIANCE' is the only supported mode in v0.1 (§6.4.2). */
    readonly object_lock_mode: 'COMPLIANCE';
    /** 'realtime' (write on each event) or 'batched' (job flushes outbox). */
    readonly write_cadence: 'realtime' | 'batched';
    readonly kms_key_id: string;
  };
  /** Tamper-detection check cadence (default 'hourly'). */
  readonly verify_cadence?: 'hourly' | 'daily';
}

export interface MultiRegionConfig {
  /** This region's identifier (e.g. 'us-east-1'). */
  readonly region: string;
  /** Whether this process is in the primary region (writes the barrier). */
  readonly is_primary: boolean;
  /** When non-primary, how to read the authoritative barrier. */
  readonly barrier_read?: {
    readonly authoritative_postgres_dsn: string;
    readonly statement_timeout_ms: number;
  };
}

export interface ObservabilityConfig {
  /** Prometheus metric prefix. Default 'agent_auth'. */
  readonly metric_prefix?: string;
  /** Override OTel service name. Default 'agent-auth'. */
  readonly service_name?: string;
}

export interface RecoverAccountConfig {
  /** Two-person rule threshold (default true for hot tier; false otherwise). */
  readonly two_person_rule?: boolean;
  /** Owner-approval webhook URL (signed with rotating secret per RT-19). */
  readonly approval_webhook_url?: string;
}

export interface ReconciliationConfig {
  /** Idempotency observer cadence in seconds (default 60). */
  readonly idempotency_observer_seconds?: number;
  /** Redis SET reconciliation cadence in seconds (default 300). */
  readonly redis_set_reconcile_seconds?: number;
}

export interface RevalidationConfig {
  /** Revalidate cadence: how often we re-check upstream identities. */
  readonly cadence_seconds?: number;
  /** Skew tolerance (default 5min for OAuth state replay protection). */
  readonly skew_tolerance_seconds?: number;
}

export interface FailoverConfig {
  /** Path of the readiness file written after post-promotion-reset. */
  readonly readiness_file?: string;
  /** Promote-blocking lag threshold in ms (default 10_000). */
  readonly max_apply_lag_ms?: number;
}

export interface AgentAuthConfig {
  /** 256-bit secret used by the lib for IP pseudonymization, webhook
   *  HMAC, etc. Must be stored alongside the app's other secrets. */
  readonly internal_secret: Buffer;

  /** One or more identity providers (§2.1 / §2.2 / §2.3). */
  readonly identity_providers: ReadonlyArray<IdentityProvider>;

  readonly storage: {
    readonly postgres: PostgresAdapter;
    readonly redis: RedisAdapter;
    readonly kms: KmsAdapter;
    /**
     * Optional in v0.1, recommended for production (§6.4.2). The lib's
     * `writeAuditToWorm` uses this to mirror audit rows to S3 Object Lock.
     * Production SaaS apps construct an `AwsS3WormPutter`; tests can plug
     * in `InMemoryWormPutter`. Both ship from `agent-auth/audit/worm-writer`.
     */
    readonly audit_worm?: WormPutter;
  };

  readonly rate_limit?: RateLimitConfig;
  readonly audit_log?: AuditLogConfig;
  readonly recover_account?: RecoverAccountConfig;
  readonly reconciliation?: ReconciliationConfig;
  readonly revalidation?: RevalidationConfig;
  readonly multi_region?: MultiRegionConfig;
  readonly validation?: ValidationConfig;
  readonly failover?: FailoverConfig;
  readonly observability?: ObservabilityConfig;

  /** Injectable clock for tests. */
  readonly clock?: Clock;
}

/**
 * Resolved config — every optional field has a value. Internal helpers take
 * `ResolvedConfig` so they don't have to redo defaulting at every call site.
 */
export interface ResolvedConfig extends Required<Omit<AgentAuthConfig,
  | 'rate_limit'
  | 'audit_log'
  | 'recover_account'
  | 'reconciliation'
  | 'revalidation'
  | 'multi_region'
  | 'failover'
  | 'observability'
  | 'clock'>> {
  readonly validation: Required<Pick<ValidationConfig,
    'mode' | 'local_cache_capacity' | 'local_cache_ttl_ms' | 'redis_cache_ttl_seconds'>>;
  readonly observability: Required<Pick<ObservabilityConfig,
    'metric_prefix' | 'service_name'>>;
  readonly rate_limit?: RateLimitConfig;
  readonly audit_log?: AuditLogConfig;
  readonly recover_account?: RecoverAccountConfig;
  readonly reconciliation?: ReconciliationConfig;
  readonly revalidation?: RevalidationConfig;
  readonly multi_region?: MultiRegionConfig;
  readonly failover?: FailoverConfig;
  readonly clock?: Clock;
}

const DEFAULT_VALIDATION_MODE: ValidationMode = 'strict_uncached';

export function resolveConfig(input: AgentAuthConfig): ResolvedConfig {
  if (!input.internal_secret || input.internal_secret.length !== 32) {
    throw new Error('agent_auth_config: internal_secret must be a 32-byte Buffer');
  }
  if (!input.identity_providers || input.identity_providers.length === 0) {
    throw new Error('agent_auth_config: identity_providers must be non-empty');
  }
  if (!input.storage?.postgres || !input.storage?.redis || !input.storage?.kms) {
    throw new Error('agent_auth_config: storage.{postgres,redis,kms} are required');
  }

  const validation: Required<Pick<ValidationConfig,
    'mode' | 'local_cache_capacity' | 'local_cache_ttl_ms' | 'redis_cache_ttl_seconds'>> = {
    mode: input.validation?.mode ?? DEFAULT_VALIDATION_MODE,
    local_cache_capacity: input.validation?.local_cache_capacity ?? 1000,
    local_cache_ttl_ms: input.validation?.local_cache_ttl_ms ?? 30_000,
    redis_cache_ttl_seconds: input.validation?.redis_cache_ttl_seconds ?? 30,
  };

  const observability: Required<Pick<ObservabilityConfig,
    'metric_prefix' | 'service_name'>> = {
    metric_prefix: input.observability?.metric_prefix ?? 'agent_auth',
    service_name: input.observability?.service_name ?? 'agent-auth',
  };

  const out: ResolvedConfig = {
    internal_secret: input.internal_secret,
    identity_providers: input.identity_providers,
    storage: input.storage,
    validation,
    observability,
    ...(input.rate_limit !== undefined ? { rate_limit: input.rate_limit } : {}),
    ...(input.audit_log !== undefined ? { audit_log: input.audit_log } : {}),
    ...(input.recover_account !== undefined ? { recover_account: input.recover_account } : {}),
    ...(input.reconciliation !== undefined ? { reconciliation: input.reconciliation } : {}),
    ...(input.revalidation !== undefined ? { revalidation: input.revalidation } : {}),
    ...(input.multi_region !== undefined ? { multi_region: input.multi_region } : {}),
    ...(input.failover !== undefined ? { failover: input.failover } : {}),
    ...(input.clock !== undefined ? { clock: input.clock } : {}),
  };
  return out;
}
