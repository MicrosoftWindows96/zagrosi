-- 002 — orgs.
--
-- Tenant root. UUID v7 ID generated app-side. Soft-delete via
-- `deleted_at`; uniqueness on `slug` is a partial unique index that
-- only constrains live rows.

CREATE TABLE orgs (
    id              UUID PRIMARY KEY,
    slug            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    primary_domain  TEXT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX orgs_slug_unique_live
    ON orgs (slug)
    WHERE deleted_at IS NULL;

CREATE INDEX orgs_deleted_at_idx ON orgs (deleted_at);
