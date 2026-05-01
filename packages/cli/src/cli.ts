#!/usr/bin/env node
/**
 * `vouch` CLI — entry point.
 *
 * Sub-commands:
 *
 *   vouch migrate up       [--db <url>] [--to <version>] [--dry-run]
 *   vouch migrate down     [--db <url>] [--steps <n>] [--dry-run]
 *   vouch migrate status   [--db <url>]
 *   vouch --version
 *   vouch --help
 *
 * `--db` defaults to the `DATABASE_URL` env var. The CLI never connects
 * unless a sub-command is invoked.
 */
import { parseArgs } from 'node:util';
import { Pool } from 'pg';
import { createMigrateRunner, resolveBundledSchemaDir } from './migrate.js';

const VERSION = '0.0.0-dev';

const HELP = `vouch — identity infrastructure for AI agents

USAGE
  vouch <command> [options]

COMMANDS
  migrate up        Apply pending migrations
  migrate down      Roll back the most recent migration(s)
  migrate status    Show applied vs pending migrations
  --version         Print the CLI version
  --help            Show this help

GLOBAL OPTIONS
  --db <url>        Postgres connection string (defaults to $DATABASE_URL)
  --schema <path>   Override the SQL migrations directory
                    (defaults to the bundled schema/migrations from agent-auth)

MIGRATE UP OPTIONS
  --to <version>    Stop after applying this version (e.g. 0005)
  --dry-run         Print what would run without changing the DB

MIGRATE DOWN OPTIONS
  --steps <n>       Number of migrations to roll back (default 1)
  --dry-run         Print what would run without changing the DB

EXAMPLES
  vouch migrate up
  vouch migrate up --to 0003 --dry-run
  vouch migrate status
  vouch migrate down --steps 2
`;

async function main(argv: string[]): Promise<number> {
  if (argv.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }
  const first = argv[0];
  if (first === '--version' || first === '-v') {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (first === '--help' || first === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (first === 'migrate') {
    return migrate(argv.slice(1));
  }
  process.stderr.write(`Unknown command: ${first}\nRun \`vouch --help\` for usage.\n`);
  return 64;
}

async function migrate(args: string[]): Promise<number> {
  const sub = args[0];
  if (!sub || sub === '--help' || sub === '-h') {
    process.stdout.write(HELP);
    return sub ? 0 : 64;
  }
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: args.slice(1),
      options: {
        db: { type: 'string' },
        schema: { type: 'string' },
        to: { type: 'string' },
        steps: { type: 'string' },
        'dry-run': { type: 'boolean', default: false },
      },
      allowPositionals: false,
      strict: true,
    });
  } catch (err) {
    process.stderr.write(`Bad flags: ${(err as Error).message}\n`);
    return 64;
  }

  const dbUrl =
    (typeof parsed.values.db === 'string' ? parsed.values.db : undefined) ??
    process.env.DATABASE_URL;
  if (!dbUrl) {
    process.stderr.write(
      'No database URL: pass --db <url> or set DATABASE_URL.\n',
    );
    return 64;
  }

  const schemaDir =
    (typeof parsed.values.schema === 'string' ? parsed.values.schema : undefined) ??
    resolveBundledSchemaDir();
  const dryRun = parsed.values['dry-run'] === true;
  const toFlag = typeof parsed.values.to === 'string' ? parsed.values.to : undefined;
  const stepsFlag = typeof parsed.values.steps === 'string' ? parsed.values.steps : undefined;

  const pool = new Pool({ connectionString: dbUrl });
  const runner = createMigrateRunner({ pool, schema_dir: schemaDir });

  try {
    if (sub === 'up') {
      const upOpts: { to?: string; dryRun?: boolean } = { dryRun };
      if (toFlag !== undefined) upOpts.to = toFlag;
      const out = await runner.up(upOpts);
      if (out.length === 0) {
        process.stdout.write('Nothing to do (database is up-to-date).\n');
      } else {
        for (const r of out) {
          process.stdout.write(`applied ${r.name} in ${r.duration_ms} ms\n`);
        }
      }
      return 0;
    }
    if (sub === 'down') {
      const steps = stepsFlag !== undefined ? Number(stepsFlag) : 1;
      if (!Number.isFinite(steps) || steps < 1) {
        process.stderr.write(`Invalid --steps: ${stepsFlag}\n`);
        return 64;
      }
      const out = await runner.down({ steps, dryRun });
      if (out.length === 0) {
        process.stdout.write('Nothing to roll back (database is at version 0).\n');
      } else {
        for (const r of out) {
          process.stdout.write(`rolled back ${r.name} in ${r.duration_ms} ms\n`);
        }
      }
      return 0;
    }
    if (sub === 'status') {
      const status = await runner.status();
      process.stdout.write(`applied: ${status.applied.length}\n`);
      for (const a of status.applied) {
        process.stdout.write(`  + ${a.version}  ${a.applied_at.toISOString()}\n`);
      }
      process.stdout.write(`pending: ${status.pending.length}\n`);
      for (const p of status.pending) {
        process.stdout.write(`  - ${p.name}\n`);
      }
      return 0;
    }
    process.stderr.write(`Unknown migrate sub-command: ${sub}\n`);
    return 64;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 1;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

const code = await main(process.argv.slice(2));
process.exit(code);
