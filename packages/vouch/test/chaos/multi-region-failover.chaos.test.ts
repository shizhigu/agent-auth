/**
 * Chaos: multi-region failover scenarios. SPEC §4.4 / §12.4 / RT-18 + RT-32 + RT-34.
 *
 * The lib's barrier-read path (src/distributed/multi-region-barrier.ts)
 * gates validation in secondary regions on:
 *   - timeline_id matching the authoritative barrier (failover guard).
 *   - local replay LSN catching up to the authoritative barrier
 *     (replication-lag guard).
 *
 * This suite exercises the gate end-to-end against a real Postgres for
 * the AUTHORITATIVE side, and a fake "local replica" Postgres adapter
 * that returns controlled timeline_id + replay LSN values. validateKey
 * is called with `barrier_check` set to the lib's makeBarrierCheck so
 * we test the production code path.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  provisionFixture,
  type IntegrationFixture,
} from '../integration/setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { validateKey } from '../../src/middleware/validate-key.js';
import { makeBarrierCheck } from '../../src/distributed/multi-region-barrier.js';
import { LocalCache } from '../../src/cache/local-cache.js';
import { ServiceUnavailableError } from '../../src/errors.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

interface FakeLocalState {
  in_recovery: boolean;
  timeline_id: number;
  replay_lsn: string;
}

function makeFakeLocal(state: FakeLocalState): PostgresAdapter {
  const adapter = {
    async queryOne(text: string) {
      if (/pg_is_in_recovery/.test(text)) return { ir: state.in_recovery };
      if (/pg_control_checkpoint/.test(text)) return { timeline_id: state.timeline_id };
      if (/pg_last_wal_replay_lsn/.test(text)) return { lsn: state.replay_lsn };
      return null;
    },
  };
  return adapter as unknown as PostgresAdapter;
}

describe('chaos: multi-region failover (SPEC §4.4 / RT-18 / RT-32 / RT-34)', () => {
  let fix: IntegrationFixture;
  let bearer: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    // Seed the cluster so the authoritative barrier has a real LSN past 0/0.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('mr-acc', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', 'mr-1', 'Iv1.mr', 'github.com', 'medium',
                 'mr-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const key_id = `agk_${randomBytes(6).toString('base64url')}`;
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
         VALUES ($1, $2, $3, $4, $5, $6, ARRAY['read'], 'cold', 1, 'active')`,
      [
        acc!.id,
        ident!.id,
        key_id,
        key_hash,
        pepper.version,
        secret.toString('base64url').slice(0, 8),
      ],
    );
    bearer = `${key_id}.${secret.toString('base64url')}`;
    // Advance the barrier so it's well past 0/0.
    await fix.postgres.query(
      `UPDATE agent_revocation_barrier
          SET last_lsn = pg_current_wal_insert_lsn()
        WHERE id = 1`,
    );
  }, 240_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  function deps(barrier_check?: () => Promise<void>) {
    return {
      postgres: fix.postgres,
      redis: fix.redis,
      kms: fix.kms,
      localCache: new LocalCache({ capacity: 100, ttl_ms: 30_000 }),
      redis_cache_ttl_seconds: 30,
      ...(barrier_check ? { barrier_check } : {}),
    };
  }

  it('control: validateKey passes when local replica is the primary itself', async () => {
    // pg_is_in_recovery=false on the "local" — barrier_check short-circuits.
    const localPg = makeFakeLocal({
      in_recovery: false,
      timeline_id: 1,
      replay_lsn: '0/0',
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local: localPg,
      on_lag: 'fail_closed',
    });
    const ctx = await validateKey(bearer, deps(check));
    expect(ctx.identity.subject).toBe('mr-1');
  });

  it('RT-32 / RT-34: timeline mismatch surfaces 503 failover_in_progress', async () => {
    // Authoritative barrier has timeline_id=1; local thinks it's still
    // on timeline 99 (post-failover, RB-8 not yet run).
    const localPg = makeFakeLocal({
      in_recovery: true,
      timeline_id: 99,
      replay_lsn: '0/0',
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local: localPg,
      on_lag: 'fail_closed',
    });
    let caught: unknown;
    try {
      await validateKey(bearer, deps(check));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ServiceUnavailableError);
    expect((caught as ServiceUnavailableError).code).toBe('failover_in_progress');
  });

  it('RT-18: replica behind barrier rejects with region_replication_stale', async () => {
    const localPg = makeFakeLocal({
      in_recovery: true,
      timeline_id: 1, // matches authoritative
      replay_lsn: '0/0', // way behind barrier
    });
    const check = makeBarrierCheck({
      primary: fix.postgres,
      local: localPg,
      on_lag: 'fail_closed',
    });
    let caught: unknown;
    try {
      await validateKey(bearer, deps(check));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(ServiceUnavailableError);
    expect((caught as ServiceUnavailableError).code).toBe('region_replication_stale');
  });
});
