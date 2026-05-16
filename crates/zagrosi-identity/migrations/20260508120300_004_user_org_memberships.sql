-- 004 — user_org_memberships.
--
-- Many-to-many link between users and orgs with a per-membership role
-- placeholder (full RBAC arrives in the tenant-isolation layer). `joined_via` records
-- the auth path that minted the membership; `jit_provisioned_at` is
-- non-null for memberships created by SSO/SCIM JIT flows.
--
-- FK to users/orgs is declared without ON DELETE CASCADE because the
-- application layer (the persistence layer) handles soft-delete cascade.

CREATE TABLE user_org_memberships (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users (id),
    org_id              UUID NOT NULL REFERENCES orgs (id),
    basic_role          TEXT NOT NULL DEFAULT 'member',
    joined_via          TEXT NOT NULL CHECK (joined_via IN ('password','oidc','saml','scim','manual')),
    jit_provisioned_at  TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX user_org_memberships_user_org_unique_live
    ON user_org_memberships (user_id, org_id)
    WHERE deleted_at IS NULL;

CREATE INDEX user_org_memberships_org_id_idx ON user_org_memberships (org_id);
CREATE INDEX user_org_memberships_user_id_idx ON user_org_memberships (user_id);
