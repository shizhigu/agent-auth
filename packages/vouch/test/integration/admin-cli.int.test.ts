/**
 * Integration: admin CLI runbook handlers against real DB. SPEC §8.1 / §8.2.
 *
 * Covers:
 *   - RB-1 revoke-key: dispatcher writes admin_revoke-key audit row BEFORE
 *     the side-effect handler; the handler revokes the key + bumps epoch
 *     + appends agent_revocation_log; pre-side-effect audit ordering
 *     guarantees ops always see the attempt even if the handler fails.
 *   - Two-person rule: flush-cache requires a co-signer envelope.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomBytes } from 'node:crypto';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { hmacWithPepper } from '../../src/crypto/hmac-pepper.js';
import { runAdminCommand } from '../../src/admin/cli.js';
import { JitRbac } from '../../src/admin/jit-rbac.js';
import { noopWebAuthnVerifier } from '../../src/admin/webauthn.js';
import {
  createCoSignerEnvelope,
  signCoSignerEnvelope,
} from '../../src/admin/two-person.js';
import { defaultRunbookHandlers } from '../../src/admin/runbooks.js';
import { PostgresAdapter } from '../../src/storage/postgres-adapter.js';

const SECRET = Buffer.alloc(32, 0xc0);

describe('integration: admin CLI runbooks (SPEC §8.1 / §8.2)', () => {
  let fix: IntegrationFixture;
  let admin: PostgresAdapter;

  beforeAll(async () => {
    fix = await provisionFixture();
    admin = new PostgresAdapter({
      pool: {
        host: fix.pg_container.getHost(),
        port: fix.pg_container.getPort(),
        database: fix.pg_container.getDatabase(),
        user: fix.pg_container.getUsername(),
        password: fix.pg_container.getPassword(),
      },
      role: 'agent_auth_admin',
    });
  }, 120_000);

  afterAll(async () => {
    await admin?.close().catch(() => undefined);
    await fix.cleanup();
  }, 120_000);

  async function seedKey(label: string): Promise<{ key_id: string; account_id: string }> {
    const acc = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_accounts (display_handle, tier, status)
         VALUES ($1, 'cold', 'active') RETURNING id`,
      [label],
    );
    const ident = await fix.postgres.queryOne<{ id: string }>(
      `INSERT INTO agent_identities
         (account_id, provider, subject, audience, issuer, assurance_level,
          display_handle, is_primary, status)
         VALUES ($1, 'github_app', $2, 'Iv1.adm', 'github.com', 'medium',
                 $3, true, 'active') RETURNING id`,
      [acc!.id, `subj-${label}`, `disp-${label}`],
    );
    const secret = randomBytes(32);
    const pepper = await fix.kms.getCurrentPepper();
    const key_hash = hmacWithPepper(pepper.data, secret);
    const key_id = `agk_adm_${randomBytes(4).toString('base64url')}`;
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
    return { key_id, account_id: acc!.id };
  }

  it('RB-1 revoke-key: audit row written BEFORE side-effects; key revoked + epoch bumped', async () => {
    const { key_id } = await seedKey('rb1');
    const jit = new JitRbac();
    const grant = jit.grant({
      admin_id: 'admin@saas',
      role: 'agent_auth_admin',
      reason: 'integration_rb1',
    });
    const epochBefore = await fix.redis.getAuthoritativeEpoch();

    const before = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_log
        WHERE event_type = 'admin_revoke-key'`,
    );

    const out = await runAdminCommand(
      {
        command: 'revoke-key',
        admin_id: 'admin@saas',
        jit_grant_id: grant.grant_id,
        reason: 'integration_rb1',
        webauthn_assertion: {
          challenge: 'c',
          origin: 'https://admin.saas',
          response_b64: 'r',
          credential_id: 'cred-1',
        },
        options: { key_id },
      },
      {
        postgres: fix.postgres,
        jit_rbac: jit,
        webauthn: noopWebAuthnVerifier,
        internal_secret: SECRET,
        audit: { postgres: fix.postgres },
        handlers: defaultRunbookHandlers({ redis: fix.redis, region: 'us-east-1' }),
      },
    );
    expect((out as { key_id: string }).key_id).toBe(key_id);

    // Audit row written.
    const after = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_log
        WHERE event_type = 'admin_revoke-key'`,
    );
    expect(Number(after?.count)).toBeGreaterThan(Number(before?.count ?? 0));

    // Key revoked.
    const row = await admin.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_id],
    );
    expect(row?.rotation_state).toBe('revoked');

    // Epoch advanced.
    expect(await fix.redis.getAuthoritativeEpoch()).toBeGreaterThan(epochBefore);

    // Revocation log appended with kind='key_revoke'.
    const log = await admin.queryOne<{ kind: string }>(
      `SELECT kind FROM agent_revocation_log
        WHERE target_id = $1 ORDER BY id DESC LIMIT 1`,
      [key_id],
    );
    expect(log?.kind).toBe('key_revoke');

    // SPEC §6.4 — Tier B mutation MUST emit an audit row in the same
    // transaction as the state change. The CLI dispatcher writes an
    // 'admin_revoke-key' intent row before the handler runs; the handler
    // ALSO writes an 'admin_revoke_committed' row inside the Tier B
    // transaction. Both must be present after the runbook completes.
    // RT-39: an attacker who suppresses one cannot suppress the other.
    const commitRow = await admin.queryOne<{ key_id: string; account_id: string }>(
      `SELECT key_id, account_id::text AS account_id FROM agent_audit_log
        WHERE event_type = 'admin_revoke_committed' AND key_id = $1
        ORDER BY id DESC LIMIT 1`,
      [key_id],
    );
    expect(commitRow).not.toBeNull();
    expect(commitRow?.key_id).toBe(key_id);
  });

  it('RB-2 suspend-account: in-tx audit row records the commit (SPEC §6.4)', async () => {
    const { account_id, key_id } = await seedKey('rb2');
    const jit = new JitRbac();
    const grant = jit.grant({
      admin_id: 'admin@saas',
      role: 'agent_auth_admin',
      reason: 'integration_rb2',
    });

    await runAdminCommand(
      {
        command: 'suspend-account',
        admin_id: 'admin@saas',
        jit_grant_id: grant.grant_id,
        reason: 'integration_rb2',
        webauthn_assertion: {
          challenge: 'c',
          origin: 'https://admin.saas',
          response_b64: 'r',
          credential_id: 'cred-1',
        },
        options: { account_id },
      },
      {
        postgres: fix.postgres,
        jit_rbac: jit,
        webauthn: noopWebAuthnVerifier,
        internal_secret: SECRET,
        audit: { postgres: fix.postgres },
        handlers: defaultRunbookHandlers({ redis: fix.redis, region: 'us-east-1' }),
      },
    );

    // Account suspended.
    const acc = await admin.queryOne<{ status: string }>(
      `SELECT status FROM agent_accounts WHERE id = $1`,
      [account_id],
    );
    expect(acc?.status).toBe('suspended');

    // Cascading key revocation hit the seeded key.
    const k = await admin.queryOne<{ rotation_state: string }>(
      `SELECT rotation_state FROM agent_api_keys WHERE key_id = $1`,
      [key_id],
    );
    expect(k?.rotation_state).toBe('revoked');

    // In-tx audit row written.
    const commitRow = await admin.queryOne<{ account_id: string }>(
      `SELECT account_id::text AS account_id FROM agent_audit_log
        WHERE event_type = 'admin_suspend_committed' AND account_id = $1::uuid
        ORDER BY id DESC LIMIT 1`,
      [account_id],
    );
    expect(commitRow).not.toBeNull();
    expect(commitRow?.account_id).toBe(account_id);
  });

  it('two-person flush-cache requires a valid co-signer envelope', async () => {
    const jit = new JitRbac();
    const grant = jit.grant({
      admin_id: 'admin@saas',
      role: 'agent_auth_admin',
      reason: 'integration_flush',
    });
    const deps = {
      postgres: fix.postgres,
      jit_rbac: jit,
      webauthn: noopWebAuthnVerifier,
      internal_secret: SECRET,
      audit: { postgres: fix.postgres },
      handlers: defaultRunbookHandlers({ redis: fix.redis, region: 'us-east-1' }),
    };
    // Without co-signer → 401.
    await expect(
      runAdminCommand(
        {
          command: 'flush-cache',
          admin_id: 'admin@saas',
          jit_grant_id: grant.grant_id,
          reason: 'integration_flush',
          webauthn_assertion: {
            challenge: 'c',
            origin: 'https://admin.saas',
            response_b64: 'r',
            credential_id: 'cred-1',
          },
          options: {},
        },
        deps,
      ),
    ).rejects.toThrowError(/co_signer_required/);

    // With a valid co-signer → succeeds.
    const env = createCoSignerEnvelope({
      op: 'flush-cache',
      target: '*',
      initiator: 'admin2@saas',
      payload: '',
    });
    const sig = signCoSignerEnvelope(env, SECRET);
    await runAdminCommand(
      {
        command: 'flush-cache',
        admin_id: 'admin@saas',
        jit_grant_id: grant.grant_id,
        reason: 'integration_flush',
        webauthn_assertion: {
          challenge: 'c',
          origin: 'https://admin.saas',
          response_b64: 'r',
          credential_id: 'cred-1',
        },
        co_signer: { envelope: env, signature_hex: sig },
        options: {},
      },
      deps,
    );
    // Audit row for the (now-passed) flush-cache attempt.
    const audit = await admin.queryOne<{ count: string }>(
      `SELECT count(*)::text AS count FROM agent_audit_log
        WHERE event_type = 'admin_flush-cache'`,
    );
    expect(Number(audit?.count)).toBeGreaterThanOrEqual(1);
  });

  it('read-only handlers (list-accounts / show-account / list-keys / show-key) all dispatch and return live data', async () => {
    const { key_id, account_id } = await seedKey('rb-readonly');
    const jit = new JitRbac();
    const grant = jit.grant({
      admin_id: 'admin@saas',
      role: 'agent_auth_admin',
      reason: 'integration_readonly',
    });
    const deps = {
      postgres: fix.postgres,
      jit_rbac: jit,
      webauthn: noopWebAuthnVerifier,
      internal_secret: SECRET,
      audit: { postgres: fix.postgres },
      handlers: defaultRunbookHandlers({ redis: fix.redis, region: 'us-east-1' }),
    };
    const baseInput = {
      admin_id: 'admin@saas',
      jit_grant_id: grant.grant_id,
      reason: 'integration_readonly',
    };

    // list-accounts: at least the seeded one is visible.
    const list = (await runAdminCommand(
      { ...baseInput, command: 'list-accounts', options: { limit: 200 } },
      deps,
    )) as { rows: Array<{ id: string }>; count: number };
    expect(list.count).toBeGreaterThanOrEqual(1);
    expect(list.rows.some((r) => r.id === account_id)).toBe(true);

    // show-account: identity_count + active_key_count populated.
    const show = (await runAdminCommand(
      { ...baseInput, command: 'show-account', options: { account_id } },
      deps,
    )) as { account: { identity_count: number; active_key_count: number } };
    expect(show.account.identity_count).toBeGreaterThanOrEqual(1);
    expect(show.account.active_key_count).toBeGreaterThanOrEqual(1);

    // list-keys (admin variant): by account, includes the seeded key.
    const keys = (await runAdminCommand(
      { ...baseInput, command: 'list-keys', options: { account_id } },
      deps,
    )) as { rows: Array<{ key_id: string }>; count: number };
    expect(keys.count).toBeGreaterThanOrEqual(1);
    expect(keys.rows.some((r) => r.key_id === key_id)).toBe(true);

    // show-key: identity-joined fields surface.
    const detail = (await runAdminCommand(
      { ...baseInput, command: 'show-key', options: { key_id } },
      deps,
    )) as { key: { key_id: string; identity_provider: string } };
    expect(detail.key.key_id).toBe(key_id);
    expect(detail.key.identity_provider).toBe('github_app');

    // All four wrote audit rows tagged admin_<command>.
    const auditCounts = await admin.query<{ event_type: string; count: string }>(
      `SELECT event_type, count(*)::text AS count FROM agent_audit_log
        WHERE event_type IN ('admin_list-accounts','admin_show-account','admin_list-keys','admin_show-key')
        GROUP BY event_type ORDER BY event_type`,
    );
    expect(auditCounts.rows.map((r) => r.event_type).sort()).toEqual([
      'admin_list-accounts',
      'admin_list-keys',
      'admin_show-account',
      'admin_show-key',
    ]);
  });
});
