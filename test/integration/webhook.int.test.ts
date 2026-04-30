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
import { createHmac, randomUUID } from 'node:crypto';
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
});
