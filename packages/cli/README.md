# @vouch/cli

Command-line tooling for [Vouch](https://github.com/shizhigu/agent-auth) — applies the lib's bundled SQL migrations against your Postgres in one command.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

## Install

```bash
npm install -D @vouch/cli
# or as a one-off:
npx @vouch/cli migrate status
```

## Commands

```
vouch migrate up        Apply pending migrations
vouch migrate down      Roll back the most recent migration(s)
vouch migrate status    Show applied vs pending migrations
```

### `vouch migrate up`

Applies any migrations the database hasn't seen yet, in `NNNN_*.sql` order. Each migration runs inside a transaction; if it fails, nothing is recorded and the next run picks up where you left off.

```bash
DATABASE_URL=postgres://… vouch migrate up
# applied 0001_init in 142 ms
# applied 0002_audit in 89 ms
# …
```

Flags:
- `--db <url>` — Postgres connection string (defaults to `$DATABASE_URL`).
- `--to <version>` — stop after applying this version (e.g. `--to 0003`).
- `--dry-run` — print what would run, don't change the database.
- `--schema <path>` — override the SQL directory (advanced; defaults to the
  bundled `agent-auth/schema/migrations`).

### `vouch migrate down`

Rolls back the last `--steps` migrations (default 1). Each migration's `.down.sql` is run inside a transaction.

```bash
vouch migrate down --steps 2
# rolled back 0006_recover_pending_approval in 18 ms
# rolled back 0005_audit_chain_utc in 12 ms
```

If a migration has no `.down.sql`, the command refuses to roll it back (you'll get a clear error message asking you to handle it manually).

### `vouch migrate status`

Shows which migrations are applied and which are pending.

```bash
vouch migrate status
# applied: 4
#   + 0001  2026-04-30T19:36:17.123Z
#   + 0002  2026-04-30T19:36:17.205Z
#   + 0003  2026-04-30T19:36:17.301Z
#   + 0004  2026-04-30T19:36:17.412Z
# pending: 2
#   - 0005_audit_chain_utc
#   - 0006_recover_pending_approval
```

## How tracking works

The CLI maintains a `vouch_migrations` table:

```sql
CREATE TABLE IF NOT EXISTS vouch_migrations (
  version    TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

It's created automatically the first time you run any migrate command. Want a different name? Pass `--tracking-table <name>` (alphanumeric + underscore only).

## Programmatic use

```ts
import { Pool } from 'pg';
import { createMigrateRunner, resolveBundledSchemaDir } from '@vouch/cli/migrate';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const runner = createMigrateRunner({
  pool,
  schema_dir: resolveBundledSchemaDir(),
});

const status = await runner.status();
console.log(`pending: ${status.pending.length}`);
const results = await runner.up();
console.log(`applied ${results.length} migrations`);

await pool.end();
```

## License

[MIT](../../LICENSE) © 2026 Agentic Flow LLC
