-- 001 — Roles + extensions.
--
-- Enables `pgcrypto` for `gen_random_bytes` (used for token-prefix
-- entropy generation in the API-token surface and the service-token surface). UUID v7 IDs are
-- generated app-side via `uuid::Uuid::now_v7()`, so `gen_random_uuid`
-- is intentionally not used.
--
-- Includes a placeholder no-op block for the upcoming tenant-isolation
-- RLS roles (`zagrosi_app NOBYPASSRLS`, `zagrosi_migrate`). Today this
-- migration must run cleanly on the dev superuser path; the
-- tenant-isolation layer replaces the placeholder with real `CREATE ROLE`
-- statements.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
    -- Placeholder for the tenant-isolation RLS roles: zagrosi_app, zagrosi_migrate.
    -- No-op on the dev superuser path; the tenant-isolation layer lights up real CREATE ROLE.
    RAISE NOTICE 'identity: rls roles placeholder (tenant-isolation layer will add zagrosi_app/zagrosi_migrate)';
END $$;
