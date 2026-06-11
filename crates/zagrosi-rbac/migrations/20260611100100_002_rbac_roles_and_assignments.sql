-- rbac 002 — custom roles, role entries, role assignments.
--
-- Built-in role *definitions* (grant sets) live in code (section-07) and
-- are never DB rows — only bindings are stored. `role_assignments` binds
-- a user to either a built-in role name or a custom role, XOR-enforced.
--
-- `custom_role_entries` deliberately has NO `deleted_at`: entry sets are
-- hard-replaced wholesale (replace-on-write PUT semantics, orchestrated
-- by the section-09 service layer) — hence the DELETE grant for
-- `zagrosi_app` on that one table.
--
-- `capability` stays TEXT at the schema level; the 12-string catalog is
-- code-versioned (`zagrosi_core::Capability`) and validated by the
-- service layer. The composite FK `(custom_role_id, org_id)` pins the
-- denormalized org to its parent role's org, so an entry can never
-- reference a foreign org's role.

CREATE TABLE custom_roles (
    id          UUID PRIMARY KEY,             -- UUIDv7, app-side
    org_id      UUID NOT NULL REFERENCES orgs (id),
    name        TEXT NOT NULL,
    description TEXT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ NULL,
    -- Composite target for custom_role_entries' denormalized-org FK.
    CONSTRAINT custom_roles_id_org_unique UNIQUE (id, org_id)
);

-- Live names are unique per org, case-insensitively.
CREATE UNIQUE INDEX custom_roles_org_name_unique_live
    ON custom_roles (org_id, lower(name))
    WHERE deleted_at IS NULL;

CREATE TABLE custom_role_entries (
    id             UUID PRIMARY KEY,          -- UUIDv7, app-side
    custom_role_id UUID NOT NULL,
    org_id         UUID NOT NULL,             -- denormalized for RLS
    capability     TEXT NOT NULL,             -- catalog-validated by the service layer
    effect         TEXT NOT NULL CHECK (effect IN ('grant','deny')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT custom_role_entries_role_org_fk
        FOREIGN KEY (custom_role_id, org_id) REFERENCES custom_roles (id, org_id)
);

-- Entry-set load shape (section-07), org_id leading.
CREATE INDEX custom_role_entries_org_role_idx
    ON custom_role_entries (org_id, custom_role_id);

CREATE TABLE role_assignments (
    id             UUID PRIMARY KEY,          -- UUIDv7, app-side
    org_id         UUID NOT NULL REFERENCES orgs (id),
    user_id        UUID NOT NULL REFERENCES users (id),
    builtin_role   TEXT NULL
        CHECK (builtin_role IS NULL OR builtin_role IN
               ('org_owner','org_admin','workspace_admin','member','guest','external')),
    custom_role_id UUID NULL,
    node_id        UUID NOT NULL,
    created_by     UUID NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ NULL,
    -- Exactly one of builtin_role / custom_role_id.
    CONSTRAINT role_assignments_role_xor
        CHECK ((builtin_role IS NULL) <> (custom_role_id IS NULL)),
    -- Org-pinned composite FKs: FK integrity checks bypass RLS, so a
    -- plain id reference would let an org-A insert point at org-B's
    -- node/role. Pinning (x, org_id) makes that unrepresentable —
    -- same mechanism as custom_role_entries' role/org pin below.
    CONSTRAINT role_assignments_node_org_fk
        FOREIGN KEY (node_id, org_id) REFERENCES resource_nodes (id, org_id),
    CONSTRAINT role_assignments_role_org_fk
        FOREIGN KEY (custom_role_id, org_id) REFERENCES custom_roles (id, org_id)
);

-- No duplicate live bindings (same user, node, role).
CREATE UNIQUE INDEX role_assignments_binding_unique_live
    ON role_assignments (user_id, node_id,
                         coalesce(builtin_role, ''),
                         coalesce(custom_role_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE deleted_at IS NULL;

-- Per-user entry-set load shape (section-07), org_id leading.
CREATE INDEX role_assignments_org_user_idx
    ON role_assignments (org_id, user_id)
    WHERE deleted_at IS NULL;

-- Node-keyed cascade shape (soft_delete_node_cascade; backfill step 4).
CREATE INDEX role_assignments_node_live_idx
    ON role_assignments (node_id)
    WHERE deleted_at IS NULL;

-- Tenant isolation (P1) + verb matrix (REVOKE neutralizes identity 024's
-- default-privileges safety net; see rbac migration 001 header).
SELECT zagrosi_enable_rls('custom_roles', 'p1');
SELECT zagrosi_enable_rls('custom_role_entries', 'p1');
SELECT zagrosi_enable_rls('role_assignments', 'p1');

REVOKE ALL ON custom_roles FROM zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT SELECT, INSERT, UPDATE ON custom_roles TO zagrosi_app;
GRANT SELECT ON custom_roles TO zagrosi_maintenance;

REVOKE ALL ON custom_role_entries FROM zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT SELECT, INSERT, DELETE ON custom_role_entries TO zagrosi_app;
GRANT SELECT ON custom_role_entries TO zagrosi_maintenance;

REVOKE ALL ON role_assignments FROM zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT SELECT, INSERT, UPDATE ON role_assignments TO zagrosi_app;
GRANT SELECT ON role_assignments TO zagrosi_maintenance;
