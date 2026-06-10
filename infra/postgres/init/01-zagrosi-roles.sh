#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Bootstrap the four Zagrosi runtime roles on a FRESH volume (initdb hooks
# never run on existing data directories — recreate the volume to apply).
#
# Runs as the container superuser, which is the supported creation path:
# BYPASSRLS can only be conferred by a superuser, and migrations run as
# zagrosi_migrate (identity migration 021 asserts the attributes and fails
# loudly when this bootstrap was skipped).
#
# Passwords come from the environment (.env): no secrets in SQL files, no
# passwords in migrations.

set -euo pipefail

: "${ZAGROSI_PG_MIGRATE_PASSWORD:?ZAGROSI_PG_MIGRATE_PASSWORD must be set in .env}"
: "${ZAGROSI_PG_APP_PASSWORD:?ZAGROSI_PG_APP_PASSWORD must be set in .env}"
: "${ZAGROSI_PG_AUTH_PASSWORD:?ZAGROSI_PG_AUTH_PASSWORD must be set in .env}"
: "${ZAGROSI_PG_MAINTENANCE_PASSWORD:?ZAGROSI_PG_MAINTENANCE_PASSWORD must be set in .env}"

target_db="${POSTGRES_DB:-zagrosi}"

psql -v ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${target_db}" \
    -v migrate_password="${ZAGROSI_PG_MIGRATE_PASSWORD}" \
    -v app_password="${ZAGROSI_PG_APP_PASSWORD}" \
    -v auth_password="${ZAGROSI_PG_AUTH_PASSWORD}" \
    -v maintenance_password="${ZAGROSI_PG_MAINTENANCE_PASSWORD}" \
    -v db="${target_db}" <<-'EOSQL'
	DO $$ BEGIN
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_migrate') THEN
	    CREATE ROLE zagrosi_migrate LOGIN NOSUPERUSER BYPASSRLS;
	  END IF;
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_app') THEN
	    CREATE ROLE zagrosi_app LOGIN NOSUPERUSER NOBYPASSRLS;
	  END IF;
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_auth') THEN
	    CREATE ROLE zagrosi_auth LOGIN NOSUPERUSER NOBYPASSRLS;
	  END IF;
	  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_maintenance') THEN
	    CREATE ROLE zagrosi_maintenance LOGIN NOSUPERUSER BYPASSRLS;
	  END IF;
	END $$;
	ALTER ROLE zagrosi_migrate PASSWORD :'migrate_password';
	ALTER ROLE zagrosi_app PASSWORD :'app_password';
	ALTER ROLE zagrosi_auth PASSWORD :'auth_password';
	ALTER ROLE zagrosi_maintenance PASSWORD :'maintenance_password';
	GRANT CONNECT ON DATABASE :"db"
	  TO zagrosi_migrate, zagrosi_app, zagrosi_auth, zagrosi_maintenance;
	GRANT CREATE, TEMP ON DATABASE :"db" TO zagrosi_migrate;
	GRANT CREATE, USAGE ON SCHEMA public TO zagrosi_migrate;
	GRANT USAGE ON SCHEMA public TO zagrosi_app, zagrosi_auth, zagrosi_maintenance;
EOSQL

echo "zagrosi roles bootstrapped for database ${target_db}"
