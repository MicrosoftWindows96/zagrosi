-- 018 — users SCIM columns.
--
-- SCIM 2.0 (RFC 7643) requires every `User` resource to expose
-- `active` (boolean), `externalId` (opaque IdP-assigned identifier),
-- and `meta.version` (an opaque ETag). The first two map onto new
-- columns on `users`; `meta.version` is derived from `updated_at`
-- combined with a per-row monotonic `row_version` counter that
-- increments on every PATCH/PUT (the row's logical mutation count
-- is independent of `updated_at`'s wall-clock value, so the ETag
-- distinguishes back-to-back writes that land within the same
-- timestamp granularity).
--
-- All three columns are nullable / defaulted so the migration is
-- safe against existing rows. `active` defaults to TRUE so legacy
-- rows behave as before. `external_id` is unique per `(org_id,
-- external_id)` only when both `external_id IS NOT NULL` and the
-- user is live (`deleted_at IS NULL`) AND has a matching live
-- membership in the org — uniqueness is therefore enforced via a
-- partial unique index on `user_org_memberships.scim_external_id`
-- (added in migration 019 alongside the SCIM external-id column on
-- the membership row), not on `users` directly. `users.external_id`
-- here is the SCIM v0.1 placeholder for the *primary* IdP-assigned
-- identifier; per-org SCIM external IDs live on the membership row.

ALTER TABLE users
    ADD COLUMN active BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN external_id TEXT NULL,
    ADD COLUMN row_version BIGINT NOT NULL DEFAULT 0;

CREATE INDEX users_active_idx ON users (active) WHERE deleted_at IS NULL;
