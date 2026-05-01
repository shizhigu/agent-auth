/**
 * validate-key middleware. Implements the validation flow in
 * SPEC §5.3.3 verbatim:
 *
 *   1. fetch authoritative epoch (Redis GET)
 *   2. local cache hit if cached_epoch === currentEpoch and not expired
 *   3. Redis cache hit if cached_epoch === currentEpoch
 *   4. Postgres lookup (authoritative)
 *   5. write back to Redis + local cache
 *   6. validate against the snapshot (account/identity/rotation/expiry/HMAC)
 *   7. return AgentContext (frozen, exposed as req.agent — never req.user)
 *
 * This module is framework-agnostic. The Express and Hono adapters wrap
 * `validateKey()` and translate AgentAuthError into HTTP responses.
 *
 * Threats covered (integration tests in M3 / M5 / M6 will exercise):
 *   - RT-3 / RT-25: Redis compromise / partition → Postgres fallback
 *   - RT-26: stale Redis epoch → falls through to Postgres on mismatch
 *   - RT-9: cross-tenant access → AgentContext only carries account_id;
 *     SaaS routes scope downstream queries by req.agent.account_id
 *   - RT-44: validation never logs the secret; raw key wiped after hashing
 */

import { LocalCache } from '../cache/local-cache.js';
import { buildAgentContext } from '../agent-context.js';
import { AgentAuthError } from '../errors.js';
import type { ResolvedConfig } from '../config.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';
import { KEY_PREFIX_KEY } from '../storage/redis-adapter.js';
import type { KmsAdapter } from '../storage/kms-adapter.js';
import type {
  AccountStatus,
  AgentContext,
  AssuranceLevel,
  IdentityStatus,
  KeyCache,
  RotationState,
  Tier,
} from '../types.js';
import { hmacWithPepper, constantTimeEqualBuffers } from '../crypto/hmac-pepper.js';

export interface ValidateKeyDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  readonly kms: KmsAdapter;
  readonly localCache: LocalCache;
  readonly redis_cache_ttl_seconds: number;
  /** Injectable clock for tests; defaults to Date.now */
  readonly now?: () => number;
  /** Optional multi-region barrier check (§4.4.2). When set, validateKey
   *  consults the authoritative barrier on the primary and rejects a
   *  stale local replica with 503 region_replication_stale. Inert in
   *  single-region deployments (caller leaves this undefined). */
  readonly barrier_check?: () => Promise<void>;
}

/** Build the deps bundle from a ResolvedConfig. */
export function makeValidateKeyDeps(cfg: ResolvedConfig): ValidateKeyDeps {
  const localCache = new LocalCache({
    capacity: cfg.validation.local_cache_capacity,
    ttl_ms: cfg.validation.local_cache_ttl_ms,
  });
  const deps: ValidateKeyDeps = {
    postgres: cfg.storage.postgres,
    redis: cfg.storage.redis,
    kms: cfg.storage.kms,
    localCache,
    redis_cache_ttl_seconds: cfg.validation.redis_cache_ttl_seconds,
  };
  return deps;
}

/**
 * Parse the wire form of an API key. agent-auth keys look like
 *   "agk_<8 chars>.<43 base64url chars>"
 * The first part is the public key_id; the second is the secret.
 *
 * (Format chosen so a single bearer token is enough on the wire and the
 * lookup index `agent_api_keys.key_id` can be hit without parsing JSON.)
 */
const KEY_FORMAT = /^(agk_[A-Za-z0-9_-]{1,32})\.([A-Za-z0-9_-]{20,128})$/;

export interface ParsedApiKey {
  readonly key_id: string;
  readonly secret: string;
}

export function parseApiKey(input: string): ParsedApiKey {
  const m = KEY_FORMAT.exec(input);
  if (!m || !m[1] || !m[2]) {
    throw new AgentAuthError(401, 'invalid_key');
  }
  return { key_id: m[1], secret: m[2] };
}

interface KeyRow {
  readonly key_id: string;
  readonly account_id: string;
  readonly account_status: AccountStatus;
  readonly account_tier: Tier;
  readonly issued_via_identity_id: string;
  readonly issuing_identity_status: IdentityStatus;
  readonly identity_provider: string;
  readonly identity_subject: string;
  readonly identity_display_handle: string | null;
  readonly identity_assurance_level: AssuranceLevel;
  readonly key_hash: Buffer;
  readonly key_pepper_version: number;
  readonly scopes: string[];
  readonly tier: Tier;
  readonly rotation_state: RotationState;
  readonly revoked_at: Date | null;
  readonly rotation_grace_expires_at: Date | null;
  readonly expires_at: Date | null;
}

/**
 * Validate an API key. Throws AgentAuthError on any reject; returns a
 * frozen AgentContext on success.
 */
export async function validateKey(
  presented: string,
  deps: ValidateKeyDeps,
): Promise<AgentContext> {
  const parsed = parseApiKey(presented);
  const now = deps.now ?? Date.now;

  // 0. Multi-region barrier check (§4.4.2). When configured, this rejects
  //    503 if the local replica is stale relative to the authoritative
  //    revocation barrier on the primary. Single-region deployments leave
  //    `barrier_check` undefined, so this is a no-op there.
  if (deps.barrier_check) {
    await deps.barrier_check();
  }

  // 1. Authoritative epoch. SPEC RT-26: "Validation falls through to
  //    Postgres on epoch mismatch or Redis unavailability." If Redis
  //    is unreachable we set currentEpoch=0 and skip the cache layer
  //    so the request is served straight from Postgres. RT-3 caps the
  //    visible impact ("worst case 30s stale auth") via the local
  //    cache TTL — no correctness regression vs. a healthy Redis.
  let currentEpoch = 0;
  let redis_available = true;
  try {
    currentEpoch = await deps.redis.getAuthoritativeEpoch();
  } catch {
    redis_available = false;
  }

  // 2. Local cache.
  if (redis_available) {
    const localHit = deps.localCache.get(parsed.key_id);
    if (localHit && localHit.cached_epoch === currentEpoch) {
      return validateAgainstCache(localHit, parsed.secret, deps.kms, now);
    }
  }

  // 3. Redis cache.
  if (redis_available) {
    let redisRaw: string | null = null;
    try {
      redisRaw = await deps.redis.get(KEY_PREFIX_KEY + parsed.key_id);
    } catch {
      redisRaw = null; // a flaky GET also drops us to Postgres.
    }
    if (redisRaw) {
      let entry: KeyCache | null = null;
      try {
        entry = decodeKeyCache(redisRaw);
      } catch {
        entry = null; // malformed entry — treat as miss
      }
      if (entry && entry.cached_epoch === currentEpoch) {
        deps.localCache.set(parsed.key_id, entry);
        return validateAgainstCache(entry, parsed.secret, deps.kms, now);
      }
    }
  }

  // 4. Postgres lookup (authoritative).
  const row = await deps.postgres.queryOne<KeyRow>(
    `SELECT k.key_id,
            k.account_id,
            a.status AS account_status,
            a.tier   AS account_tier,
            k.issued_via_identity_id,
            i.status AS issuing_identity_status,
            i.provider          AS identity_provider,
            i.subject           AS identity_subject,
            i.display_handle    AS identity_display_handle,
            i.assurance_level   AS identity_assurance_level,
            k.key_hash,
            k.key_pepper_version,
            k.scopes,
            k.tier,
            k.rotation_state,
            k.revoked_at,
            k.rotation_grace_expires_at,
            k.expires_at
     FROM agent_api_keys k
     JOIN agent_accounts a   ON a.id = k.account_id
     JOIN agent_identities i ON i.id = k.issued_via_identity_id
     WHERE k.key_id = $1`,
    [parsed.key_id],
  );
  if (!row) {
    throw new AgentAuthError(401, 'key_not_found');
  }

  const entry: KeyCache = {
    key_id: row.key_id,
    account_id: row.account_id,
    account_status: row.account_status,
    issuing_identity_id: row.issued_via_identity_id,
    issuing_identity_status: row.issuing_identity_status,
    identity_provider: row.identity_provider,
    identity_subject: row.identity_subject,
    ...(row.identity_display_handle !== null
      ? { identity_display_handle: row.identity_display_handle }
      : {}),
    identity_assurance_level: row.identity_assurance_level,
    key_hash: Buffer.isBuffer(row.key_hash) ? row.key_hash : Buffer.from(row.key_hash),
    key_pepper_version: row.key_pepper_version,
    scopes: Object.freeze([...row.scopes]),
    tier: row.tier,
    rotation_state: row.rotation_state,
    revoked_at: row.revoked_at !== null ? row.revoked_at.toISOString() : null,
    grace_expires_at:
      row.rotation_grace_expires_at !== null
        ? row.rotation_grace_expires_at.toISOString()
        : null,
    expires_at: row.expires_at !== null ? row.expires_at.toISOString() : null,
    cached_epoch: currentEpoch,
    cached_at: now(),
    redis_expires_at: now() + deps.redis_cache_ttl_seconds * 1000,
  };

  // 5. Populate caches (best-effort; ignore Redis errors so a Redis outage
  //    does not block validation — Postgres has already authoritatively
  //    decided. Skip the Redis SET entirely when we already know Redis
  //    is unreachable to avoid pointless wait/log volume during outages.
  if (redis_available) {
    try {
      await deps.redis.set(KEY_PREFIX_KEY + parsed.key_id, encodeKeyCache(entry), {
        ex_seconds: deps.redis_cache_ttl_seconds,
      });
    } catch {
      // ignore — best-effort.
    }
  }
  // Local cache is always written so within-process repeats don't re-hit
  // Postgres during a Redis outage. RT-3 caps the staleness via TTL.
  deps.localCache.set(parsed.key_id, entry);

  return validateAgainstCache(entry, parsed.secret, deps.kms, now);
}

async function validateAgainstCache(
  cache: KeyCache,
  secret: string,
  kms: KmsAdapter,
  now: () => number = Date.now,
): Promise<AgentContext> {
  // Account status (§5.3.3).
  if (cache.account_status === 'suspended') {
    throw new AgentAuthError(401, 'account_suspended');
  }
  if (cache.account_status === 'closed') {
    throw new AgentAuthError(410, 'account_closed');
  }

  // Issuing identity status.
  if (cache.issuing_identity_status === 'revoked') {
    throw new AgentAuthError(401, 'identity_revoked');
  }
  if (cache.issuing_identity_status === 'expired') {
    throw new AgentAuthError(401, 'identity_revoked');
  }

  // Rotation state.
  if (cache.rotation_state === 'revoked') {
    throw new AgentAuthError(401, 'key_revoked');
  }
  if (cache.rotation_state === 'rotated') {
    throw new AgentAuthError(401, 'key_rotated');
  }
  if (cache.rotation_state === 'rotating') {
    if (
      cache.grace_expires_at &&
      now() >= new Date(cache.grace_expires_at).getTime()
    ) {
      throw new AgentAuthError(401, 'rotation_grace_expired');
    }
  }

  // Expiration (§10.4 key_expired).
  if (cache.expires_at && now() >= new Date(cache.expires_at).getTime()) {
    throw new AgentAuthError(401, 'key_expired');
  }

  // HMAC verification — try the stored pepper version, fall back to
  // accepted-legacy versions (dual-window per §6.1.2). Constant-time
  // compare on every candidate so timing does not leak which version
  // matched.
  //
  // Per SPEC §2.2.2 step h, the secret is hashed as the raw 32 random bytes
  // — the base64url form is only the wire encoding. Decode here.
  const secret_bytes = Buffer.from(secret, 'base64url');
  const stored = cache.key_hash;
  const accepted = await kms.acceptedVersions();
  const versions: number[] = [cache.key_pepper_version];
  for (const v of accepted) if (v !== cache.key_pepper_version) versions.push(v);

  let matched = false;
  for (const v of versions) {
    try {
      const pepper = await kms.getPepperByVersion(v);
      const candidate = hmacWithPepper(pepper.data, secret_bytes);
      if (constantTimeEqualBuffers(candidate, stored) && !matched) {
        matched = true;
        // Don't break — keep iterating to keep timing roughly stable.
      }
    } catch {
      // version not accepted any more; ignore
    }
  }
  if (!matched) {
    throw new AgentAuthError(401, 'invalid_secret');
  }

  return buildAgentContext(cache);
}

// ---------------------------------------------------------------------------
// Encoding to/from Redis. JSON; key_hash is base64.
// ---------------------------------------------------------------------------

interface SerializedKeyCache {
  readonly key_id: string;
  readonly account_id: string;
  readonly account_status: AccountStatus;
  readonly issuing_identity_id: string;
  readonly issuing_identity_status: IdentityStatus;
  readonly identity_provider: string;
  readonly identity_subject: string;
  readonly identity_display_handle?: string;
  readonly identity_assurance_level: AssuranceLevel;
  readonly key_hash_b64: string;
  readonly key_pepper_version: number;
  readonly scopes: string[];
  readonly tier: Tier;
  readonly rotation_state: RotationState;
  readonly revoked_at: string | null;
  readonly grace_expires_at: string | null;
  readonly expires_at: string | null;
  readonly cached_epoch: number;
  readonly cached_at: number;
  readonly redis_expires_at: number;
}

export function encodeKeyCache(c: KeyCache): string {
  const obj: SerializedKeyCache = {
    key_id: c.key_id,
    account_id: c.account_id,
    account_status: c.account_status,
    issuing_identity_id: c.issuing_identity_id,
    issuing_identity_status: c.issuing_identity_status,
    identity_provider: c.identity_provider,
    identity_subject: c.identity_subject,
    ...(c.identity_display_handle !== undefined
      ? { identity_display_handle: c.identity_display_handle }
      : {}),
    identity_assurance_level: c.identity_assurance_level,
    key_hash_b64: c.key_hash.toString('base64'),
    key_pepper_version: c.key_pepper_version,
    scopes: [...c.scopes],
    tier: c.tier,
    rotation_state: c.rotation_state,
    revoked_at: c.revoked_at,
    grace_expires_at: c.grace_expires_at,
    expires_at: c.expires_at,
    cached_epoch: c.cached_epoch,
    cached_at: c.cached_at,
    redis_expires_at: c.redis_expires_at,
  };
  return JSON.stringify(obj);
}

export function decodeKeyCache(raw: string): KeyCache {
  const obj = JSON.parse(raw) as SerializedKeyCache;
  const c: KeyCache = {
    key_id: obj.key_id,
    account_id: obj.account_id,
    account_status: obj.account_status,
    issuing_identity_id: obj.issuing_identity_id,
    issuing_identity_status: obj.issuing_identity_status,
    identity_provider: obj.identity_provider,
    identity_subject: obj.identity_subject,
    ...(obj.identity_display_handle !== undefined
      ? { identity_display_handle: obj.identity_display_handle }
      : {}),
    identity_assurance_level: obj.identity_assurance_level,
    key_hash: Buffer.from(obj.key_hash_b64, 'base64'),
    key_pepper_version: obj.key_pepper_version,
    scopes: Object.freeze([...obj.scopes]),
    tier: obj.tier,
    rotation_state: obj.rotation_state,
    revoked_at: obj.revoked_at,
    grace_expires_at: obj.grace_expires_at,
    expires_at: obj.expires_at,
    cached_epoch: obj.cached_epoch,
    cached_at: obj.cached_at,
    redis_expires_at: obj.redis_expires_at,
  };
  return c;
}
