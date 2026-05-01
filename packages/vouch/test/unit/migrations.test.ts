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

  it('every up-migration has a corresponding down-migration (§3.17)', () => {
    const all = readAll().map((m) => m.name);
    const ups = all.filter((n) => n.endsWith('.sql') && !n.endsWith('.down.sql'));
    const downs = all.filter((n) => n.endsWith('.down.sql'));
    for (const u of ups) {
      const expected = u.replace(/\.sql$/, '.down.sql');
      expect(downs, `missing down migration for ${u}`).toContain(expected);
    }
  });

  it('down-migrations are wrapped in BEGIN/COMMIT and use IF EXISTS guards', () => {
    const downs = readAll().filter((m) => m.name.endsWith('.down.sql'));
    expect(downs.length).toBeGreaterThanOrEqual(4);
    for (const m of downs) {
      expect(m.body).toMatch(/^\s*BEGIN\s*;/m);
      expect(m.body).toMatch(/COMMIT\s*;\s*$/);
      // DROP statements must use IF EXISTS so re-running the rollback is safe.
      const dropTable = m.body.match(/DROP TABLE\b(?! IF EXISTS)/g);
      const dropTrigger = m.body.match(/DROP TRIGGER\b(?! IF EXISTS)/g);
      const dropFunction = m.body.match(/DROP FUNCTION\b(?! IF EXISTS)/g);
      expect(dropTable, `${m.name} has unguarded DROP TABLE`).toBeNull();
      expect(dropTrigger, `${m.name} has unguarded DROP TRIGGER`).toBeNull();
      expect(dropFunction, `${m.name} has unguarded DROP FUNCTION`).toBeNull();
    }
  });

  it('up-migration filenames are monotonic (0001, 0002, ...)', () => {
    const numbers = readAll()
      .filter((m) => !m.name.endsWith('.down.sql'))
      .map((m) => Number(m.name.slice(0, 4)));
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

  it('app role is append-only on agent_audit_log (INSERT/SELECT but no UPDATE/DELETE)', () => {
    const audit = readAll().find((m) => m.name === '0002_audit.sql')!;
    // GRANT must contain INSERT (mandatory). SELECT is also granted so the
    // writer's RETURNING clause and the in-process verifier can read.
    expect(audit.body).toMatch(
      /GRANT\s+INSERT,\s*SELECT\s+ON\s+agent_audit_log\s+TO\s+agent_auth_app/,
    );
    // No GRANT UPDATE / DELETE for app on agent_audit_log — preserves §3.16
    // append-only invariant.
    const block = audit.body
      .split(/\n\s*\n/)
      .filter((b) => /agent_auth_app/.test(b) && /agent_audit_log/.test(b))
      .join('\n');
    expect(/GRANT[^;]*UPDATE[^;]*agent_audit_log[^;]*agent_auth_app/.test(block)).toBe(false);
    expect(/GRANT[^;]*DELETE[^;]*agent_audit_log[^;]*agent_auth_app/.test(block)).toBe(false);
  });
});
