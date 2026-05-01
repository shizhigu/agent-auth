import { describe, it, expect, beforeEach } from 'vitest';
import {
  runAdminCommand,
  type AdminCommandHandler,
  type AdminDispatchDeps,
} from '../../src/admin/cli.js';
import { JitRbac } from '../../src/admin/jit-rbac.js';
import {
  createCoSignerEnvelope,
  signCoSignerEnvelope,
} from '../../src/admin/two-person.js';
import { noopWebAuthnVerifier } from '../../src/admin/webauthn.js';
import type { PostgresAdapter } from '../../src/storage/postgres-adapter.js';
import type { WebAuthnVerifier } from '../../src/admin/webauthn.js';

const SECRET = Buffer.alloc(32, 5);

class FakePg {
  audit: Array<Record<string, unknown>> = [];
  async query<R>(text: string, params: ReadonlyArray<unknown> = []) {
    if (/INSERT INTO agent_audit_log/.test(text)) {
      this.audit.push({ event_type: params[4] });
      return {
        rows: [{ id: '1', ts: new Date(), row_hash: Buffer.alloc(32), prev_hash: Buffer.alloc(32) }] as unknown as R[],
        rowCount: 1,
      };
    }
    return { rows: [], rowCount: 0 };
  }
  async queryOne<R>(text: string, params: ReadonlyArray<unknown> = []): Promise<R | null> {
    const out = await this.query<R>(text, params);
    return (out.rows[0] as R) ?? null;
  }
  async transaction<T>(fn: (c: FakePg) => Promise<T>): Promise<T> {
    return fn(this);
  }
}

function asAdapter(d: FakePg): PostgresAdapter {
  return d as unknown as PostgresAdapter;
}

function makeDeps(opts: {
  jit?: JitRbac;
  webauthn?: WebAuthnVerifier;
  handlers?: AdminDispatchDeps['handlers'];
} = {}): AdminDispatchDeps {
  const pg = new FakePg();
  const jit = opts.jit ?? new JitRbac();
  return {
    postgres: asAdapter(pg),
    jit_rbac: jit,
    webauthn: opts.webauthn ?? noopWebAuthnVerifier,
    internal_secret: SECRET,
    audit: { postgres: asAdapter(pg) },
    handlers: opts.handlers ?? {},
  };
}

describe('runAdminCommand (SPEC §8.1 / §8.2)', () => {
  let jit: JitRbac;
  let grant_id: string;
  let calls: Array<{ command: string }>;
  let handlers: AdminDispatchDeps['handlers'];

  beforeEach(() => {
    jit = new JitRbac();
    const grant = jit.grant({
      admin_id: 'admin@saas',
      role: 'agent_auth_admin',
      reason: 'incident-2026-04-30',
    });
    grant_id = grant.grant_id;
    calls = [];
    const handler: AdminCommandHandler = {
      async run(input) {
        calls.push({ command: input.command });
        return { ok: true, command: input.command };
      },
    };
    handlers = {
      'list-keys': handler,
      'show-key': handler,
      'revoke-key': handler,
      'flush-cache': handler,
    } as AdminDispatchDeps['handlers'];
  });

  it('read-only command runs without WebAuthn or co-signer', async () => {
    const out = await runAdminCommand(
      {
        command: 'list-keys',
        admin_id: 'admin@saas',
        jit_grant_id: grant_id,
        reason: 'list',
        options: {},
      },
      makeDeps({ jit, handlers }),
    );
    expect(out).toEqual({ ok: true, command: 'list-keys' });
    expect(calls).toHaveLength(1);
  });

  it('destructive command requires a WebAuthn assertion', async () => {
    await expect(
      runAdminCommand(
        {
          command: 'revoke-key',
          admin_id: 'admin@saas',
          jit_grant_id: grant_id,
          reason: 'compromise',
          options: { key_id: 'agk_x' },
        },
        makeDeps({ jit, handlers }),
      ),
    ).rejects.toThrow(/webauthn_required/);
  });

  it('destructive command runs after WebAuthn assertion', async () => {
    const out = await runAdminCommand(
      {
        command: 'revoke-key',
        admin_id: 'admin@saas',
        jit_grant_id: grant_id,
        reason: 'compromise',
        webauthn_assertion: {
          challenge: 'c',
          origin: 'https://admin.saas',
          response_b64: 'r',
          credential_id: 'cred-1',
        },
        options: { key_id: 'agk_x' },
      },
      makeDeps({ jit, handlers }),
    );
    expect(out).toMatchObject({ command: 'revoke-key' });
  });

  it('two-person command rejects without a co-signer envelope', async () => {
    await expect(
      runAdminCommand(
        {
          command: 'flush-cache',
          admin_id: 'admin@saas',
          jit_grant_id: grant_id,
          reason: 'incident-flush',
          webauthn_assertion: {
            challenge: 'c',
            origin: 'https://admin.saas',
            response_b64: 'r',
            credential_id: 'cred-1',
          },
          options: {},
        },
        makeDeps({ jit, handlers }),
      ),
    ).rejects.toThrow(/co_signer_required/);
  });

  it('two-person command runs after valid co-signer signature', async () => {
    const env = createCoSignerEnvelope({
      op: 'flush-cache',
      target: '*',
      initiator: 'admin2@saas',
      payload: '',
    });
    const sig = signCoSignerEnvelope(env, SECRET);
    const out = await runAdminCommand(
      {
        command: 'flush-cache',
        admin_id: 'admin@saas',
        jit_grant_id: grant_id,
        reason: 'incident-flush',
        webauthn_assertion: {
          challenge: 'c',
          origin: 'https://admin.saas',
          response_b64: 'r',
          credential_id: 'cred-1',
        },
        co_signer: { envelope: env, signature_hex: sig },
        options: {},
      },
      makeDeps({ jit, handlers }),
    );
    expect(out).toMatchObject({ command: 'flush-cache' });
  });

  it('invalid jit grant rejects 401', async () => {
    await expect(
      runAdminCommand(
        {
          command: 'list-keys',
          admin_id: 'admin@saas',
          jit_grant_id: 'bogus',
          reason: 'list',
          options: {},
        },
        makeDeps({ jit, handlers }),
      ),
    ).rejects.toThrow(/jit_grant_not_found/);
  });

  it('unknown command surfaces 400', async () => {
    await expect(
      runAdminCommand(
        {
          command: 'show-key',
          admin_id: 'admin@saas',
          jit_grant_id: grant_id,
          reason: 'show',
          options: {},
        },
        makeDeps({ jit, handlers: {} }),
      ),
    ).rejects.toThrow(/unknown_command/);
  });
});
