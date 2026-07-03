#!/usr/bin/env bash
# =============================================================================
# db-init.sh — MSTE PostgreSQL initialisation
#
# Executed once by the postgres container's docker-entrypoint.sh on first
# start (when the data directory is empty). Runs as the postgres superuser.
#
# What this script does:
#   1. Creates the Hoppscotch database and its dedicated role
#   2. Creates the MSTE web-UI role scoped to the mste database
#   3. Installs required extensions on both databases
#   4. Configures least-privilege grants for both application roles
#
# Required environment variables (set in docker-compose.yml):
#   POSTGRES_USER        — superuser name (already exists at this point)
#   WEB_DB_USER          — MSTE web app DB user
#   WEB_DB_PASSWORD      — MSTE web app DB password
#   HOPP_DB_USER         — Hoppscotch DB user
#   HOPP_DB_PASSWORD     — Hoppscotch DB password
# =============================================================================

set -euo pipefail

echo "[db-init] Starting MSTE database initialisation..."

# Validate that all required env vars are present before doing anything
: "${WEB_DB_USER:?WEB_DB_USER must be set}"
: "${WEB_DB_PASSWORD:?WEB_DB_PASSWORD must be set}"
: "${HOPP_DB_USER:?HOPP_DB_USER must be set}"
: "${HOPP_DB_PASSWORD:?HOPP_DB_PASSWORD must be set}"


# =============================================================================
# Helper — run SQL as the Postgres superuser
# =============================================================================
run_sql() {
    psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" "$@"
}


# =============================================================================
# 1. MSTE web-UI role
#    The 'mste' database already exists (created via POSTGRES_DB env var).
#    We just need the application role with a limited grant.
# =============================================================================

echo "[db-init] Creating MSTE web-UI role: ${WEB_DB_USER}"

run_sql --dbname postgres <<-SQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (
            SELECT FROM pg_catalog.pg_roles WHERE rolname = '${WEB_DB_USER}'
        ) THEN
            CREATE ROLE "${WEB_DB_USER}"
                WITH LOGIN
                     PASSWORD '${WEB_DB_PASSWORD}'
                     NOSUPERUSER
                     NOCREATEDB
                     NOCREATEROLE;
        ELSE
            -- Update password in case it changed
            ALTER ROLE "${WEB_DB_USER}" WITH PASSWORD '${WEB_DB_PASSWORD}';
        END IF;
    END
    \$\$;

    -- Allow the role to connect and use the mste database
    GRANT CONNECT ON DATABASE mste TO "${WEB_DB_USER}";
SQL

# Grant schema-level privileges inside the mste database
run_sql --dbname mste <<-SQL
    -- Install extensions (superuser required)
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE EXTENSION IF NOT EXISTS pg_trgm;

    -- Schema access
    GRANT USAGE  ON SCHEMA public TO "${WEB_DB_USER}";
    GRANT CREATE ON SCHEMA public TO "${WEB_DB_USER}";

    -- Tables, sequences, functions that already exist
    GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO "${WEB_DB_USER}";
    GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "${WEB_DB_USER}";
    GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO "${WEB_DB_USER}";

    -- Tables, sequences, functions created in the future
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON TABLES    TO "${WEB_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON SEQUENCES TO "${WEB_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON FUNCTIONS TO "${WEB_DB_USER}";
SQL

echo "[db-init] MSTE web-UI role configured."


# =============================================================================
# 2. Hoppscotch role + database
# =============================================================================

echo "[db-init] Creating Hoppscotch role: ${HOPP_DB_USER}"

run_sql --dbname postgres <<-SQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (
            SELECT FROM pg_catalog.pg_roles WHERE rolname = '${HOPP_DB_USER}'
        ) THEN
            CREATE ROLE "${HOPP_DB_USER}"
                WITH LOGIN
                     PASSWORD '${HOPP_DB_PASSWORD}'
                     NOSUPERUSER
                     NOCREATEDB
                     NOCREATEROLE;
        ELSE
            ALTER ROLE "${HOPP_DB_USER}" WITH PASSWORD '${HOPP_DB_PASSWORD}';
        END IF;
    END
    \$\$;
SQL

# Create the hoppscotch database (must be done outside a transaction block)
echo "[db-init] Creating hoppscotch database..."
run_sql --dbname postgres <<-SQL
    SELECT 'CREATE DATABASE hoppscotch OWNER "${HOPP_DB_USER}"'
    WHERE NOT EXISTS (
        SELECT FROM pg_catalog.pg_database WHERE datname = 'hoppscotch'
    )\gexec
SQL

# Grant full ownership inside the hoppscotch database
run_sql --dbname hoppscotch <<-SQL
    CREATE EXTENSION IF NOT EXISTS pgcrypto;

    -- Hoppscotch runs its own Prisma migrations, so it needs full schema rights
    GRANT ALL PRIVILEGES ON SCHEMA public TO "${HOPP_DB_USER}";
    GRANT CREATE ON SCHEMA public TO "${HOPP_DB_USER}";

    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON TABLES    TO "${HOPP_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON SEQUENCES TO "${HOPP_DB_USER}";
    ALTER DEFAULT PRIVILEGES IN SCHEMA public
        GRANT ALL PRIVILEGES ON FUNCTIONS TO "${HOPP_DB_USER}";
SQL

echo "[db-init] Hoppscotch role and database configured."


# =============================================================================
# 3. Verify
# =============================================================================

echo "[db-init] Verification:"
run_sql --dbname postgres --tuples-only <<-SQL
    SELECT
        r.rolname        AS role,
        r.rolcanlogin    AS can_login,
        d.datname        AS has_connect_on
    FROM pg_roles r
    LEFT JOIN pg_database d
           ON has_database_privilege(r.rolname, d.datname, 'CONNECT')
          AND d.datname IN ('mste', 'hoppscotch')
    WHERE r.rolname IN ('${WEB_DB_USER}', '${HOPP_DB_USER}')
    ORDER BY r.rolname, d.datname;
SQL

echo "[db-init] Initialisation complete."
