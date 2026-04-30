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
