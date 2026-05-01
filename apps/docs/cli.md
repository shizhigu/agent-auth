# Migrations CLI

`@vouch/cli` ships a `vouch` binary that applies, rolls back, and inspects the SQL migrations bundled with `agent-auth`.

## Install

```bash
npm install -D @vouch/cli
# or one-shot:
npx @vouch/cli migrate status
```

## Commands

### `vouch migrate up`

Applies pending migrations in `NNNN_*.sql` order. Each runs inside a transaction; failure rolls back and the version is NOT recorded.

```bash
DATABASE_URL=postgres://… vouch migrate up
# applied 0001_init in 142 ms
# applied 0002_audit in 89 ms
# …
```

**Flags:**
- `--db <url>` — Postgres connection string (defaults to `$DATABASE_URL`).
- `--to <version>` — stop after applying this version (e.g. `--to 0003`).
- `--dry-run` — print what would run, don't change the database.
- `--schema <path>` — override the SQL directory (advanced; defaults to the bundled `agent-auth/schema/migrations`).

### `vouch migrate down`

Rolls back the last `--steps` migrations (default 1) by running each one's `.down.sql` inside a transaction.

```bash
vouch migrate down --steps 2
# rolled back 0006_recover_pending_approval in 18 ms
# rolled back 0005_audit_chain_utc in 12 ms
```

If a migration has no `.down.sql`, the command refuses to roll it back. You'll get a clear error message asking you to handle it manually.

### `vouch migrate status`

Shows applied vs pending migrations.

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

## Tracking table

The CLI maintains:

```sql
CREATE TABLE IF NOT EXISTS vouch_migrations (
  version    TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Created automatically the first time you run any migrate command. If the table is empty but the database already has a partial schema (e.g. you migrated by hand before installing the CLI), see [Adopting an existing database](#adopting-an-existing-database).

## Tips

::: tip Running as the right role
Migrations need to create the `agent_auth_app/admin/migrator/readonly` Postgres roles (DDL). The connection should be a superuser or have `CREATEROLE` + DDL privileges. Production-style: connect as `agent_auth_migrator` (after a one-time superuser bootstrap that creates the role).
:::

::: tip CI / CD pipelines
A typical deploy pipeline:
```bash
npx vouch migrate status            # log current state
npx vouch migrate up --dry-run      # show pending without changing
# (manual approval gate)
npx vouch migrate up                # apply
```
:::

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
if (status.pending.length > 0) {
  console.log(`Applying ${status.pending.length} migrations…`);
  await runner.up();
}

await pool.end();
```

## Adopting an existing database

If you applied earlier migrations by hand and now want to use the CLI for the rest:

```sql
-- Tell the tracking table what's already been applied:
INSERT INTO vouch_migrations (version, name) VALUES
  ('0001', '0001_init'),
  ('0002', '0002_audit'),
  ('0003', '0003_revocation'),
  ('0004', '0004_idempotency')
ON CONFLICT DO NOTHING;
```

Then `vouch migrate up` will only apply 0005, 0006, etc.
