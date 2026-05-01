/**
 * Unit tests for the migrate runner — exercises the file-listing logic
 * (sort order, .down.sql discovery, malformed names) without spinning up
 * a real Postgres. The actual SQL execution lives in apps/demo's
 * end-to-end run.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Pool } from 'pg';
import { createMigrateRunner } from '../src/migrate.js';

function withTempSchemaDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'vouch-migrate-test-'));
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function writeMigration(dir: string, version: string, name: string, sql: string, downSql?: string) {
  const stem = `${version}_${name}`;
  writeFileSync(join(dir, `${stem}.sql`), sql);
  if (downSql !== undefined) {
    writeFileSync(join(dir, `${stem}.down.sql`), downSql);
  }
}

// Stub Pool — never actually connects, just records what would have been
// queried. Sufficient for asserting list() doesn't talk to the DB.
function stubPool(): Pool {
  return {} as unknown as Pool;
}

describe('createMigrateRunner — list()', () => {
  let tmp: ReturnType<typeof withTempSchemaDir> | null = null;
  afterEach(() => {
    tmp?.cleanup();
    tmp = null;
  });

  it('discovers NNNN_<name>.sql files in version order', () => {
    tmp = withTempSchemaDir();
    writeMigration(tmp.dir, '0003', 'three', '-- up', '-- down');
    writeMigration(tmp.dir, '0001', 'one', '-- up');
    writeMigration(tmp.dir, '0002', 'two', '-- up', '-- down');
    const runner = createMigrateRunner({ pool: stubPool(), schema_dir: tmp.dir });
    const list = runner.list();
    expect(list.map((m) => m.version)).toEqual(['0001', '0002', '0003']);
    expect(list.map((m) => m.name)).toEqual(['0001_one', '0002_two', '0003_three']);
  });

  it('attaches a down_path only when the .down.sql file exists', () => {
    tmp = withTempSchemaDir();
    writeMigration(tmp.dir, '0001', 'has_down', '-- up', '-- down');
    writeMigration(tmp.dir, '0002', 'no_down', '-- up'); // no down
    const runner = createMigrateRunner({ pool: stubPool(), schema_dir: tmp.dir });
    const list = runner.list();
    expect(list[0]?.down_path).toMatch(/0001_has_down\.down\.sql$/);
    expect(list[1]?.down_path).toBeNull();
  });

  it('ignores non-numeric and malformed filenames', () => {
    tmp = withTempSchemaDir();
    writeMigration(tmp.dir, '0001', 'good', '-- up');
    writeFileSync(join(tmp.dir, 'README.md'), 'docs');
    writeFileSync(join(tmp.dir, '12_short.sql'), '-- not 4 digits');
    writeFileSync(join(tmp.dir, '0002-no-underscore.sql'), '-- bad sep');
    writeFileSync(join(tmp.dir, '0003_.sql'), '-- empty name');
    // Only `0001_good.sql` matches the strict NNNN_<name>.sql pattern.
    // README, the 2-digit prefix, the no-underscore form, and the
    // empty-descriptive-part form are all rejected.
    const runner = createMigrateRunner({ pool: stubPool(), schema_dir: tmp.dir });
    const list = runner.list();
    expect(list.map((m) => m.version)).toEqual(['0001']);
  });

  it('throws a clear error when the schema dir does not exist', () => {
    const runner = createMigrateRunner({
      pool: stubPool(),
      schema_dir: '/tmp/vouch-this-path-does-not-exist-' + Date.now(),
    });
    expect(() => runner.list()).toThrow(/Cannot read schema dir/);
  });

  it('handles 4-digit versions including the boundary 9999', () => {
    tmp = withTempSchemaDir();
    writeMigration(tmp.dir, '0001', 'a', '-- a');
    writeMigration(tmp.dir, '0010', 'b', '-- b');
    writeMigration(tmp.dir, '0100', 'c', '-- c');
    writeMigration(tmp.dir, '9999', 'z', '-- z');
    const runner = createMigrateRunner({ pool: stubPool(), schema_dir: tmp.dir });
    const list = runner.list();
    expect(list.map((m) => m.version)).toEqual(['0001', '0010', '0100', '9999']);
  });

  it('rejects an invalid tracking_table name to prevent SQL injection', () => {
    tmp = withTempSchemaDir();
    writeMigration(tmp.dir, '0001', 'a', '-- a');
    expect(() =>
      createMigrateRunner({
        pool: stubPool(),
        schema_dir: tmp!.dir,
        tracking_table: 'evil"; DROP TABLE foo; --',
      }),
    ).toThrow(/Invalid identifier/);
  });
});
