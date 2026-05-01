/**
 * Integration: GitHub webhook end-to-end against real Postgres + Redis.
 *
 * Covers SPEC §2.2.4 + §2.2.5:
 *   - HMAC-verified github_app_authorization revoke payload triggers
 *     identity revoke + key cascade + account suspend (RT-24).
 *   - RT-6 replay: same delivery returns 'duplicate' status.
 *   - RT-30 collision: same delivery id with different body raises onAlert.
 *   - Cascade revoke writes revocation_log with kind='identity_revoke'.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import {
  provisionFixture,
  type IntegrationFixture,
} from './setup.js';
import { GitHubAppProvider } from '../../src/identity/github-app/browser-flow.js';
import { handleWebhookRequest } from '../../src/routes/webhooks.js';

const WEBHOOK_SECRET = 'integration-webhook-secret';

function ghSig(body: Buffer): string {
  return 'sha256=' + createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
}

describe('integration: webhook (SPEC §2.2.4 / RT-6 / RT-30)', () => {
  let fix: IntegrationFixture;
  let provider: GitHubAppProvider;
  let account_id: string;
  let identity_id: string;

  beforeAll(async () => {
    fix = await provisionFixture();
    provider = new GitHubAppProvider({
      client_id: 'Iv1.int',
      client_secret: 'cs',
      webhook_secret: WEBHOOK_SECRET,
    });

    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('hook-acc', 'cold', 'active') RETURNING id`,
    );
    account_id = acc!.id;
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', '99999', 'Iv1.int', 'github.com', 'medium',
                 'hook-octo', true, 'active') RETURNING id`,
      [account_id],
    );
    identity_id = ident!.id;
    // Seed two keys: one 'active' and one 'rotating' (with grace) so the
    // cascade walks both rotation states.
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
       VALUES ($1, $2, 'agk_hkA', $3, 1, 'aaaaaaaa', '{"read"}', 'cold', 1, 'active')`,
      [account_id, identity_id, Buffer.alloc(32, 1)],
    );
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state, rotated_at,
          rotation_grace_expires_at)
       VALUES ($1, $2, 'agk_hkB', $3, 1, 'bbbbbbbb', '{"read"}', 'cold', 1,
               'rotating', now(), now() + interval '1 hour')`,
      [account_id, identity_id, Buffer.alloc(32, 1)],
    );
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  function makeBody(): Buffer {
    return Buffer.from(
      JSON.stringify({ action: 'revoked', sender: { id: 99999, login: 'hook-octo' } }),
      'utf8',
    );
  }

  it('happy path: identity revoked, both keys cascaded, account suspended, epoch bumped', async () => {
    const body = makeBody();
    const delivery = randomUUID();
    const epochBefore = await fix.redis.getAuthoritativeEpoch();
    const out = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': ghSig(body),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery,
        },
        raw_body: body,
      },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        identity_providers: [provider],
        region: 'us-east-1',
      },
    );
    expect(out.status).toBe('processed');
    expect(new Set(out.invalidated_keys)).toEqual(new Set(['agk_hkA', 'agk_hkB']));

    const ident = await fix.postgres.queryOne<{ status: string; revocation_source: string }>(
      `SELECT status, revocation_source FROM agent_identities WHERE id = $1`,
      [identity_id],
    );
    expect(ident?.status).toBe('revoked');
    expect(ident?.revocation_source).toBe('webhook');

    const keys = await fix.postgres.query<{ key_id: string; rotation_state: string }>(
      `SELECT key_id, rotation_state FROM agent_api_keys
        WHERE account_id = $1 ORDER BY key_id`,
      [account_id],
    );
    expect(keys.rows.every((r) => r.rotation_state === 'revoked')).toBe(true);

    const acc = await fix.postgres.queryOne<{ status: string }>(
      `SELECT status FROM agent_accounts WHERE id = $1`,
      [account_id],
    );
    expect(acc?.status).toBe('suspended');

    expect(await fix.redis.getAuthoritativeEpoch()).toBeGreaterThan(epochBefore);

    const log = await fix.postgres.queryOne<{ kind: string }>(
      `SELECT kind FROM agent_revocation_log
        WHERE target_id = '99999' ORDER BY id DESC LIMIT 1`,
    );
    expect(log?.kind).toBe('identity_revoke');

    // SPEC §6.4 — webhook cascade emits an audit row in the same txn.
    const audit = await fix.postgres.queryOne<{
      event_type: string;
      account_id: string;
    }>(
      `SELECT event_type, account_id::text AS account_id FROM agent_audit_log
        WHERE event_type = 'webhook_identity_revoke' AND account_id = $1::uuid
        ORDER BY id DESC LIMIT 1`,
      [account_id],
    );
    expect(audit?.event_type).toBe('webhook_identity_revoke');
  });

  it('RT-6: replay of the same delivery returns duplicate (no extra revocation)', async () => {
    const body = makeBody();
    const delivery = randomUUID();
    const headers = {
      'x-hub-signature-256': ghSig(body),
      'x-github-event': 'github_app_authorization',
      'x-github-delivery': delivery,
    };
    const deps = {
      postgres: fix.postgres,
      redis: fix.redis,
      identity_providers: [provider],
      region: 'us-east-1',
    };
    const a = await handleWebhookRequest(
      { provider: 'github_app', headers, raw_body: body },
      deps,
    );
    const epochBefore = await fix.redis.getAuthoritativeEpoch();
    const b = await handleWebhookRequest(
      { provider: 'github_app', headers, raw_body: body },
      deps,
    );
    expect(a.status === 'processed' || a.status === 'ignored').toBe(true);
    expect(b.status).toBe('duplicate');
    expect(await fix.redis.getAuthoritativeEpoch()).toBe(epochBefore);
  });

  it('RT-30 collision: same delivery id with different body raises onAlert; existing row wins', async () => {
    const a = makeBody();
    const b = Buffer.from(
      JSON.stringify({ action: 'revoked', sender: { id: 7777 } }),
      'utf8',
    );
    const delivery = randomUUID();
    const alerts: Array<{ label: string }> = [];
    const deps = {
      postgres: fix.postgres,
      redis: fix.redis,
      identity_providers: [provider],
      region: 'us-east-1',
      onAlert: (label: string) => alerts.push({ label }),
    };
    await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': ghSig(a),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery,
        },
        raw_body: a,
      },
      deps,
    );
    await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': ghSig(b),
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery,
        },
        raw_body: b,
      },
      deps,
    );
    expect(alerts).toContainEqual({ label: 'webhook_id_collision_with_payload_mismatch' });
  });

  it('RT-42 dual-secret rotation: deliveries signed with previous secret are accepted during the window', async () => {
    // Configure a provider in the rotation window: secret_v2 is current,
    // secret_v1 is the previous value GitHub may still be using.
    const SECRET_V1 = 'rt42-prev-secret-v1';
    const SECRET_V2 = 'rt42-curr-secret-v2';
    const rotatingProvider = new GitHubAppProvider({
      client_id: 'Iv1.int',
      client_secret: 'cs',
      webhook_secret: SECRET_V2,
      webhook_secret_previous: SECRET_V1,
    });

    // Signed with the OLD secret — emulates a delivery sent mid-rotation
    // before GitHub picked up the new secret.
    const body = Buffer.from(
      JSON.stringify({ action: 'revoked', sender: { id: 333333, login: 'rt42-octo' } }),
      'utf8',
    );
    const sigOld = 'sha256=' + createHmac('sha256', SECRET_V1).update(body).digest('hex');
    const delivery = randomUUID();
    const before = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events WHERE id = $1`,
      [delivery],
    );
    expect(Number(before?.count ?? '0')).toBe(0);

    const out = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': sigOld,
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery,
        },
        raw_body: body,
      },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        identity_providers: [rotatingProvider],
        region: 'us-east-1',
      },
    );
    // Sender id has no matching identity in this fixture, so the lib treats
    // the action as a no-op revoke (status 'ignored' or 'processed' with no
    // invalidations) — but importantly NOT 'duplicate' and not 401.
    expect(['processed', 'ignored']).toContain(out.status);
    // The webhook_events row was written (delivery accepted post-HMAC).
    const after = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events WHERE id = $1`,
      [delivery],
    );
    expect(Number(after?.count ?? '0')).toBe(1);

    // Sanity: same body signed with the CURRENT secret also passes.
    const delivery2 = randomUUID();
    const sigNew = 'sha256=' + createHmac('sha256', SECRET_V2).update(body).digest('hex');
    const out2 = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': sigNew,
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery2,
        },
        raw_body: body,
      },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        identity_providers: [rotatingProvider],
        region: 'us-east-1',
      },
    );
    expect(['processed', 'ignored']).toContain(out2.status);
  });

  it('RT-42 rotation window closed: delivery signed with old secret is rejected 401', async () => {
    // Provider configured WITHOUT webhook_secret_previous (rotation done,
    // grace window closed). Old-secret traffic must fail closed.
    const closedProvider = new GitHubAppProvider({
      client_id: 'Iv1.int',
      client_secret: 'cs',
      webhook_secret: 'rt42-curr-secret-v2',
      // no webhook_secret_previous
    });

    const body = Buffer.from(
      JSON.stringify({ action: 'revoked', sender: { id: 444444 } }),
      'utf8',
    );
    const sigOld =
      'sha256=' + createHmac('sha256', 'rt42-prev-secret-v1').update(body).digest('hex');
    const delivery = randomUUID();
    const beforeCount = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events`,
    );
    await expect(
      handleWebhookRequest(
        {
          provider: 'github_app',
          headers: {
            'x-hub-signature-256': sigOld,
            'x-github-event': 'github_app_authorization',
            'x-github-delivery': delivery,
          },
          raw_body: body,
        },
        {
          postgres: fix.postgres,
          redis: fix.redis,
          identity_providers: [closedProvider],
          region: 'us-east-1',
        },
      ),
    ).rejects.toMatchObject({ status: 401 });
    // Verify-before-dedup invariant — no row inserted on HMAC failure.
    const afterCount = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events`,
    );
    expect(afterCount?.count).toBe(beforeCount?.count);
  });

  it('rejects 401-class on bad HMAC and writes nothing to agent_webhook_events', async () => {
    const body = makeBody();
    const delivery = randomUUID();
    const before = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events`,
    );
    await expect(
      handleWebhookRequest(
        {
          provider: 'github_app',
          headers: {
            'x-hub-signature-256': 'sha256=' + 'a'.repeat(64),
            'x-github-event': 'github_app_authorization',
            'x-github-delivery': delivery,
          },
          raw_body: body,
        },
        {
          postgres: fix.postgres,
          redis: fix.redis,
          identity_providers: [provider],
          region: 'us-east-1',
        },
      ),
    ).rejects.toMatchObject({ status: 401 });
    const after = await fix.postgres.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_webhook_events`,
    );
    // Verify-before-dedup: no row inserted on HMAC failure.
    expect(after?.count).toBe(before?.count);
  });

  it('redelivery of a previously-FAILED row re-processes the actions (status: failed → processed)', async () => {
    // Plant a fresh identity + key so the cascade has something to do.
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ('hook-retry', 'cold', 'active') RETURNING id`,
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', '88888', 'Iv1.int', 'github.com', 'medium',
                 'hook-retry-octo', true, 'active') RETURNING id`,
      [acc!.id],
    );
    await fix.postgres.query(
      `INSERT INTO agent_api_keys
         (account_id, issued_via_identity_id, key_id, key_hash, key_pepper_version,
          prefix, scopes, tier, version, rotation_state)
       VALUES ($1, $2, 'agk_retry', $3, 1, 'retryret', '{"read"}', 'cold', 1, 'active')`,
      [acc!.id, ident!.id, Buffer.alloc(32, 5)],
    );

    const body = Buffer.from(
      JSON.stringify({ action: 'revoked', sender: { id: 88888, login: 'hook-retry-octo' } }),
      'utf8',
    );
    const sig = ghSig(body);
    const delivery = randomUUID();

    // Plant a webhook_events row in 'failed' status — simulates a prior
    // attempt that errored (e.g., transient DB blip). The replay job /
    // GitHub redelivery should NOT short-circuit to 'duplicate'; the
    // actions need to actually run.
    // The route's payload_hash is SHA-256 of raw_body; match that exactly
    // so the body-mismatch alert path doesn't trigger.
    const real_hash = createHash('sha256').update(body).digest();
    await fix.postgres.query(
      `INSERT INTO agent_webhook_events
         (id, provider, event_type, payload_hash, status, error)
       VALUES ($1::uuid, 'github_app', 'github_app_authorization', $2, 'failed', 'simulated_blip')`,
      [delivery, real_hash],
    );

    const out = await handleWebhookRequest(
      {
        provider: 'github_app',
        headers: {
          'x-hub-signature-256': sig,
          'x-github-event': 'github_app_authorization',
          'x-github-delivery': delivery,
        },
        raw_body: body,
      },
      {
        postgres: fix.postgres,
        redis: fix.redis,
        identity_providers: [provider],
        region: 'us-east-1',
      },
    );

    // Re-processed (NOT 'duplicate'): identity revoked + key cascaded.
    expect(out.status).toBe('processed');
    expect(out.invalidated_keys).toContain('agk_retry');
    const idRow = await fix.postgres.queryOne<{ status: string }>(
      `SELECT status FROM agent_identities WHERE id = $1`,
      [ident!.id],
    );
    expect(idRow?.status).toBe('revoked');
    // The webhook_events row's status flipped to 'processed'.
    const evt = await fix.postgres.queryOne<{ status: string }>(
      `SELECT status FROM agent_webhook_events WHERE id = $1::uuid`,
      [delivery],
    );
    expect(evt?.status).toBe('processed');
  });
});
