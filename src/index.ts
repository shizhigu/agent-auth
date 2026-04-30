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
