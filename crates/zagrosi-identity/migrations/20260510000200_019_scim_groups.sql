-- 019 — SCIM groups + group memberships + per-membership external_id.
--
-- SCIM 2.0 (RFC 7643 §4.2) `Group` resources land here. Groups are
-- per-org (multi-tenant): every query is hard-anchored on `org_id`
-- via the `OrgScoped<GroupRepo>` wrapper at the repo layer, mirroring
-- the SCIM tenant-isolation invariant set in section-05.
--
-- `display_name` is the SCIM `displayName`. `external_id` is the
-- SCIM `externalId` (IdP-assigned opaque identifier; unique per
-- `(org_id, external_id)` for live rows so cross-org IdP imports
-- can reuse the same external id without colliding).
-- `row_version` is the per-row monotonic mutation counter consumed
-- by the SCIM ETag derivation (`http::scim::etag::meta_version`).
--
-- `group_memberships` is the many-to-many join. The pair
-- `(group_id, user_id)` is unique while live. Soft-delete tombstones
-- the row instead of deleting it so audit / forensic queries can
-- walk historical membership.
--
-- `user_org_memberships.scim_external_id` adds an optional per-membership
-- external id used by SCIM Users surface to disambiguate when the same
-- underlying `users` row is provisioned from multiple IdPs.

CREATE TABLE groups (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES orgs (id),
    display_name  TEXT NOT NULL,
    external_id   TEXT NULL,
    row_version   BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ NULL
);

CREATE INDEX groups_org_id_idx ON groups (org_id) WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX groups_org_display_name_unique_live
    ON groups (org_id, lower(display_name))
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX groups_org_external_id_unique_live
    ON groups (org_id, external_id)
    WHERE deleted_at IS NULL AND external_id IS NOT NULL;

CREATE TABLE group_memberships (
    id          UUID PRIMARY KEY,
    group_id    UUID NOT NULL REFERENCES groups (id),
    user_id     UUID NOT NULL REFERENCES users (id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX group_memberships_group_user_unique_live
    ON group_memberships (group_id, user_id)
    WHERE deleted_at IS NULL;

CREATE INDEX group_memberships_user_id_idx
    ON group_memberships (user_id) WHERE deleted_at IS NULL;

ALTER TABLE user_org_memberships
    ADD COLUMN scim_external_id TEXT NULL;

CREATE UNIQUE INDEX user_org_memberships_org_scim_external_unique_live
    ON user_org_memberships (org_id, scim_external_id)
    WHERE deleted_at IS NULL AND scim_external_id IS NOT NULL;
