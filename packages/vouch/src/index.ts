/**
 * Public entry point for agent-auth. SaaS providers `import { agents } from
 * 'agent-auth'` after configuring the lib. Stable surface area only — internal
 * modules under src/storage, src/identity, src/distributed, etc. are not part
 * of the published API.
 */

export { AgentAuthError, ServiceUnavailableError, isAgentAuthError } from './errors.js';
export type { AgentAuthErrorCode, AgentAuthErrorOptions } from './errors.js';

export { buildAgentContext } from './agent-context.js';

export type {
  AgentContext,
  AssuranceLevel,
  AccountStatus,
  Attestation,
  AttestationContext,
  BeginRegistrationResult,
  Clock,
  IdempotencyState,
  IdentityProvider,
  IdentityStatus,
  KeyCache,
  ParsedWebhook,
  ProviderInput,
  RevocationSource,
  RotationState,
  SessionKind,
  SessionStatus,
  Tier,
  WebhookAction,
} from './types.js';

export { RealClock } from './types.js';

export { resolveConfig } from './config.js';
export type {
  AgentAuthConfig,
  ResolvedConfig,
  ValidationConfig,
  ValidationMode,
  RateLimitConfig,
  RateLimitDimension,
  AuditLogConfig,
  MultiRegionConfig,
  ObservabilityConfig,
  RecoverAccountConfig,
  ReconciliationConfig,
  RevalidationConfig,
  FailoverConfig,
} from './config.js';

export { LocalCache } from './cache/local-cache.js';
export {
  validateKey,
  parseApiKey,
  makeValidateKeyDeps,
} from './middleware/validate-key.js';
export type { ValidateKeyDeps } from './middleware/validate-key.js';

export { expressMiddleware } from './middleware/express-adapter.js';
export type {
  ExpressAgentMiddleware,
  ExpressMiddlewareOptions,
} from './middleware/express-adapter.js';

export { honoMiddleware } from './middleware/hono-adapter.js';
export type {
  HonoAgentMiddleware,
  HonoMiddlewareOptions,
} from './middleware/hono-adapter.js';

export { generatePkcePair, deriveChallenge, verifyVerifier } from './crypto/pkce.js';
export {
  hashNewKey,
  verifyKey as verifyKeyHmac,
  hmacWithPepper,
} from './crypto/hmac-pepper.js';
export {
  computeRowHash,
  canonicalAuditText,
  verifyChain,
  ZERO_HASH,
} from './crypto/audit-hash.js';

export { PostgresAdapter } from './storage/postgres-adapter.js';
export type { AppRole, PostgresAdapterConfig } from './storage/postgres-adapter.js';

export {
  IoredisAdapter,
  InMemoryRedisAdapter,
  KEY_REVOCATION_EPOCH,
  KEY_PREFIX_KEY,
  KEY_PREFIX_ACCOUNT_KEYS,
  PUBSUB_INVALIDATE_KEY_PREFIX,
  PUBSUB_INVALIDATE_ACCOUNT_PREFIX,
  LUA_EPOCH_MAX,
} from './storage/redis-adapter.js';
export type { RedisAdapter, IoredisAdapterConfig } from './storage/redis-adapter.js';

export { AwsKmsAdapter, InMemoryKmsAdapter } from './storage/kms-adapter.js';
export type {
  KmsAdapter,
  AwsKmsAdapterConfig,
  PepperMaterial,
  EncryptedBlob,
} from './storage/kms-adapter.js';

export {
  writeAuditRow,
  writeAuditRowOnClient,
  pseudonymizeIp,
} from './audit/db-writer.js';
export type { AuditWriteInput, AuditWriteResult, AuditDbDeps } from './audit/db-writer.js';

export {
  AwsS3WormPutter,
  InMemoryWormPutter,
  writeAuditToWorm,
} from './audit/worm-writer.js';
export type {
  WormPutter,
  AwsS3WormPutterConfig,
  AuditWormConfig,
  AuditWormEvent,
  S3WormPut,
} from './audit/worm-writer.js';

// Scheduled jobs (SPEC §13.1.2). The lib provides the building blocks;
// the SaaS app composes them into its own worker process (or Kubernetes
// CronJobs / Temporal workflows / etc.).
export { reapRegistrationSessions } from './jobs/reaper.js';
export { runWebhookReplay } from './jobs/webhook-replay.js';
export { reconcileUnknownIdempotency } from './jobs/reconcile-idempotency.js';
export { verifyAuditChain } from './jobs/audit-verifier.js';
export { flushAuditOutbox } from './jobs/outbox-flusher.js';
export { reconcileAccountKeySets } from './jobs/reconcile-redis-sets.js';
export { manageAuditPartitions } from './jobs/audit-partition-manager.js';
export { expireRotationGrace } from './jobs/rotation-grace-expirer.js';
export { processAgentJobs } from './jobs/process-agent-jobs.js';
export { reapExpiredRows } from './jobs/expired-rows-reaper.js';
export type {
  ExpiredRowsReaperDeps,
  ExpiredRowsReaperResult,
} from './jobs/expired-rows-reaper.js';
export type {
  AgentJobKind,
  AgentJobRow,
  ProcessAgentJobsDeps,
  ProcessAgentJobsResult,
  JobHandler,
} from './jobs/process-agent-jobs.js';

// High-level factory — turns a flat config into a ready-to-mount auth instance.
export { vouch } from './factory.js';
export type {
  VouchInit,
  VouchInstance,
  VouchExpress,
  VouchLifecycle,
  VouchRequestContext,
  DatabaseInit,
  RedisInit,
  KmsInit,
  AwsKmsInit,
  InMemoryKmsInit,
  IdentityInit,
} from './factory.js';

// Identity providers — instances are usually built by the factory, but
// exporting them lets power users wire `identity.custom` with extra
// configuration or compose a custom IdP.
export { GitHubAppProvider } from './identity/github-app/browser-flow.js';
export type { GitHubAppProviderConfig } from './identity/github-app/browser-flow.js';
export { GoogleProvider } from './identity/google/provider.js';
export type { GoogleProviderConfig } from './identity/google/provider.js';
export { OidcProvider } from './identity/oidc/provider.js';
export type {
  OidcProviderConfig,
  OidcEndpoints,
  Fetcher as OidcFetcher,
} from './identity/oidc/provider.js';

// OpenTelemetry tracing helpers (optional).
export { instrumentLifecycle, SPAN_STATUS } from './observability/tracing.js';
export type {
  TracingConfig,
  VouchTracerLike,
  VouchSpanLike,
  SpanStatusCode,
} from './observability/tracing.js';
