import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const MIGRATIONS_DIR = join(__dirname, '..', '..', 'schema', 'migrations');

function readAll(): { name: string; body: string }[] {
  return readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((name) => ({ name, body: readFileSync(join(MIGRATIONS_DIR, name), 'utf8') }));
}

describe('SQL migrations — structural invariants (SPEC §3.17)', () => {
  it('every migration is wrapped in BEGIN/COMMIT', () => {
    for (const m of readAll()) {
      expect(m.body, `${m.name} missing BEGIN`).toMatch(/^\s*BEGIN\s*;/m);
      expect(m.body, `${m.name} missing COMMIT`).toMatch(/COMMIT\s*;\s*$/);
    }
  });

  it('migration filenames are monotonic (0001, 0002, ...)', () => {
    const numbers = readAll().map((m) => Number(m.name.slice(0, 4)));
    for (let i = 1; i < numbers.length; i++) {
      const prev = numbers[i - 1];
      const cur = numbers[i];
      expect(prev).toBeDefined();
      expect(cur).toBeDefined();
      expect((cur as number) > (prev as number)).toBe(true);
    }
  });

  it('migrations are idempotent (use IF NOT EXISTS or guarded DO blocks)', () => {
    for (const m of readAll()) {
      const createTable = m.body.match(/CREATE TABLE\b(?! IF NOT EXISTS)/g);
      const createIndex = m.body.match(/CREATE INDEX\b(?! IF NOT EXISTS)/g);
      const createUniqueIndex = m.body.match(/CREATE UNIQUE INDEX\b(?! IF NOT EXISTS)/g);
      const createDomain = m.body.match(/CREATE DOMAIN\b/g);
      const createRole = m.body.match(/CREATE ROLE\b/g);

      // CREATE TABLE / INDEX / UNIQUE INDEX must be IF NOT EXISTS unless inside a partition def.
      const tablesWithoutIfNotExists = (createTable ?? [])
        // CREATE TABLE ... PARTITION OF is allowed without IF NOT EXISTS only when guarded.
        .filter(() => true);
      // Quick check: if any are present, the file must also include IF NOT EXISTS on at least one CREATE TABLE.
      if (tablesWithoutIfNotExists.length > 0) {
        // Allow `CREATE TABLE foo PARTITION OF` to live without IF NOT EXISTS.
        // Filter those out before failing.
        const offending = m.body
          .split('\n')
          .filter((line) => /CREATE TABLE\b(?! IF NOT EXISTS)/.test(line))
          .filter((line) => !/PARTITION OF/.test(line));
        expect(offending, `${m.name} has non-idempotent CREATE TABLE`).toEqual([]);
      }
      if (createIndex) expect(createIndex.length, `${m.name} has non-idempotent CREATE INDEX`).toBe(0);
      if (createUniqueIndex)
        expect(createUniqueIndex.length, `${m.name} has non-idempotent CREATE UNIQUE INDEX`).toBe(0);

      // CREATE DOMAIN must be inside a DO block that checks pg_type
      if (createDomain) {
        expect(m.body, `${m.name} CREATE DOMAIN must be guarded by DO block`).toMatch(
          /DO\s*\$\$[\s\S]*?CREATE DOMAIN/,
        );
      }
      // CREATE ROLE must be inside a DO block that checks pg_roles
      if (createRole) {
        expect(m.body, `${m.name} CREATE ROLE must be guarded by DO block`).toMatch(
          /DO\s*\$\$[\s\S]*?CREATE ROLE/,
        );
      }
    }
  });

  it('0002_audit declares the hash chain trigger', () => {
    const audit = readAll().find((m) => m.name === '0002_audit.sql');
    expect(audit).toBeDefined();
    expect(audit!.body).toMatch(/compute_audit_row_hash/);
    expect(audit!.body).toMatch(/BEFORE INSERT ON agent_audit_log/);
  });

  it('0003_revocation enforces epoch monotonicity and barrier monotonicity', () => {
    const rev = readAll().find((m) => m.name === '0003_revocation.sql');
    expect(rev).toBeDefined();
    expect(rev!.body).toMatch(/enforce_epoch_monotonic/);
    expect(rev!.body).toMatch(/enforce_barrier_monotonic/);
  });

  it('0004_idempotency enforces transition rules and terminal-row immutability', () => {
    const idem = readAll().find((m) => m.name === '0004_idempotency.sql');
    expect(idem).toBeDefined();
    expect(idem!.body).toMatch(/enforce_idempotency_transitions/);
    expect(idem!.body).toMatch(/enforce_terminal_row_immutable/);
  });

  it('app role has INSERT-only on agent_audit_log (no UPDATE/DELETE)', () => {
    const audit = readAll().find((m) => m.name === '0002_audit.sql')!;
    // GRANT INSERT ON agent_audit_log TO agent_auth_app
    expect(audit.body).toMatch(
      /GRANT\s+INSERT\s+ON\s+agent_audit_log\s+TO\s+agent_auth_app/,
    );
    // No GRANT UPDATE / DELETE for app on agent_audit_log
    const lines = audit.body.split('\n');
    const updateGrant = lines.find(
      (l) => /GRANT[^;]*UPDATE/.test(l) && /agent_audit_log/.test(l) && /agent_auth_app/.test(l),
    );
    const deleteGrant = lines.find(
      (l) => /GRANT[^;]*DELETE/.test(l) && /agent_audit_log/.test(l) && /agent_auth_app/.test(l),
    );
    expect(updateGrant).toBeUndefined();
    expect(deleteGrant).toBeUndefined();
  });
});
