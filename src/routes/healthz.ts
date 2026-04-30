/**
 * GET /api/agent-auth/healthz — operational health probe. SPEC §10.2.
 *
 * Returns 200 with the SPEC-shaped healthy body when:
 *   - Postgres is reachable (singleton barrier row readable)
 *   - Redis is reachable (authoritative epoch readable; covers Lua scripts
 *     too since the epoch read uses the GET path that's pre-warmed)
 *   - All registered circuit breakers (if any) are not 'open'
 *
 * Returns 503 with `{status:'unhealthy', reasons:[…]}` otherwise. The
 * caller is responsible for routing the JSON to its HTTP framework with
 * the right status code.
 *
 * The lib's healthz handler does NOT touch the network outside the
 * processes it already maintains — no S3 ping, no IdP ping. Those are
 * captured indirectly via circuit-breaker state.
 */

import type { CircuitBreaker } from '../reliability/circuit-breaker.js';
import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { RedisAdapter } from '../storage/redis-adapter.js';

export interface HealthzDeps {
  readonly postgres: PostgresAdapter;
  readonly redis: RedisAdapter;
  /** Map of dependency-name → CircuitBreaker; e.g. { github_app: <breaker> }. */
  readonly circuit_breakers?: Readonly<Record<string, CircuitBreaker>>;
  /** Lib version for the health body (defaults to the package version). */
  readonly version?: string;
}

export interface HealthzHealthy {
  readonly status: 'healthy';
  readonly version: string;
  readonly timeline_id: number;
  readonly barrier_lsn: string;
  readonly redis_quorum_acks: number;
  readonly circuit_breakers: Readonly<Record<string, string>>;
}

export interface HealthzUnhealthy {
  readonly status: 'unhealthy';
  readonly reasons: ReadonlyArray<string>;
}

export type HealthzResult =
  | { http_status: 200; body: HealthzHealthy }
  | { http_status: 503; body: HealthzUnhealthy };

export async function healthz(deps: HealthzDeps): Promise<HealthzResult> {
  const reasons: string[] = [];

  // Postgres: read the singleton revocation barrier — also gives us
  // timeline_id + last_lsn for the response body.
  let timeline_id = 0;
  let barrier_lsn = '0/0';
  try {
    const row = await deps.postgres.queryOne<{
      last_lsn: string;
      timeline_id: number;
    }>(
      `SELECT last_lsn::text AS last_lsn, timeline_id
         FROM agent_revocation_barrier WHERE id = 1`,
    );
    if (!row) {
      reasons.push('postgres_barrier_missing');
    } else {
      timeline_id = row.timeline_id;
      barrier_lsn = row.last_lsn;
    }
  } catch {
    reasons.push('postgres_unreachable');
  }

  // Redis: read the authoritative epoch (cheap, also stresses the GET path).
  let redis_quorum_acks = 0;
  try {
    await deps.redis.getAuthoritativeEpoch();
    // Single-replica deployments report 1 ack; SaaS apps with replicas
    // override this via custom healthz routes.
    redis_quorum_acks = 1;
  } catch {
    reasons.push('redis_unreachable');
  }

  // Circuit breakers: surface state, flag any 'open' as a reason so
  // operators see which dependency is suspected.
  const cb_states: Record<string, string> = {};
  if (deps.circuit_breakers) {
    for (const [name, breaker] of Object.entries(deps.circuit_breakers)) {
      const state = breaker.state_();
      cb_states[name] = state;
      if (state === 'open') {
        reasons.push(`circuit_breaker_open:${name}`);
      }
    }
  }

  if (reasons.length > 0) {
    return {
      http_status: 503,
      body: { status: 'unhealthy', reasons },
    };
  }

  return {
    http_status: 200,
    body: {
      status: 'healthy',
      version: deps.version ?? '0.1.0',
      timeline_id,
      barrier_lsn,
      redis_quorum_acks,
      circuit_breakers: cb_states,
    },
  };
}
