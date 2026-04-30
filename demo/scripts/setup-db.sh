#!/usr/bin/env bash
# Apply agent-auth migrations against the demo Postgres.
#
# Idempotent: each migration uses CREATE ... IF NOT EXISTS so re-running is
# safe. Doesn't drop anything — use `docker compose down -v` to reset.

set -euo pipefail

: "${DATABASE_URL:?Set DATABASE_URL (see .env.example)}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIG_DIR="$REPO_ROOT/schema/migrations"

echo "Applying migrations from $MIG_DIR ..."

for f in "$MIG_DIR"/*.sql; do
  case "$f" in
    *.down.sql) continue ;;
  esac
  echo "  -> $(basename "$f")"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$f"
done

# The migrations define agent_auth_app / _admin / _readonly / _migrator as
# NOLOGIN roles. The SaaS connects as the docker-compose superuser
# (`postgres`) and uses SET ROLE to drop privileges per checkout. SET ROLE
# requires the connecting user to be a MEMBER of the target role, so grant
# membership now.
echo "Granting role membership to the demo Postgres user ..."
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -c "
  GRANT agent_auth_app TO postgres;
  GRANT agent_auth_admin TO postgres;
  GRANT agent_auth_readonly TO postgres;
  GRANT agent_auth_migrator TO postgres;
"

echo "Done."
