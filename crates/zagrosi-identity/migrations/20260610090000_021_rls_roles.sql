-- 021 — the four-role split (fulfils migration 001's placeholder).
--
-- Roles are cluster-level and may pre-exist (bootstrap scripts, shared
-- dev clusters), so every CREATE ROLE is guarded. The SUPPORTED creation
-- path is environment bootstrap as superuser (test-support harness,
-- compose initdb hook, managed-PG bootstrap SQL): `BYPASSRLS` can only be
-- conferred by a superuser, and migrations run as `zagrosi_migrate`
-- (non-superuser). The guards below therefore usually no-op; they exist
-- so `zagrosi_app`/`zagrosi_auth` can still be created when
-- `zagrosi_migrate` was bootstrapped with CREATEROLE, and so superuser-
-- driven legacy/one-off runs remain idempotent.
--
-- NO PASSWORDS IN MIGRATIONS. Roles are created LOGIN but unusable until
-- the environment sets a password out-of-band
-- (`ALTER ROLE ... PASSWORD ...` in bootstrap).
--
-- The migration ends with an attribute-assertion block: misprovisioned
-- environments fail HERE with an actionable message, never silently at
-- runtime (where BYPASSRLS-less maintenance jobs would see zero rows and
-- a superuser app role would bypass every policy).

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_migrate') THEN
    CREATE ROLE zagrosi_migrate LOGIN NOSUPERUSER BYPASSRLS;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_app') THEN
    CREATE ROLE zagrosi_app LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_auth') THEN
    CREATE ROLE zagrosi_auth LOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'zagrosi_maintenance') THEN
    CREATE ROLE zagrosi_maintenance LOGIN NOSUPERUSER BYPASSRLS;
  END IF;
END $$;

-- Attribute assertions: fail loudly on misprovisioning.
DO $$
DECLARE
  spec RECORD;
BEGIN
  FOR spec IN
    SELECT * FROM (VALUES
      ('zagrosi_migrate',     true),
      ('zagrosi_app',         false),
      ('zagrosi_auth',        false),
      ('zagrosi_maintenance', true)
    ) AS s(role_name, want_bypassrls)
  LOOP
    IF NOT EXISTS (
      SELECT FROM pg_roles
      WHERE rolname = spec.role_name
        AND rolcanlogin
        AND NOT rolsuper
        AND rolbypassrls = spec.want_bypassrls
    ) THEN
      RAISE EXCEPTION
        'role "%" is missing or misprovisioned: need LOGIN, NOSUPERUSER, %. '
        'Bootstrap the four zagrosi roles as superuser (BYPASSRLS cannot be '
        'conferred by zagrosi_migrate) and set passwords out-of-band, then re-run migrations.',
        spec.role_name,
        CASE WHEN spec.want_bypassrls THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END;
    END IF;
  END LOOP;
END $$;
