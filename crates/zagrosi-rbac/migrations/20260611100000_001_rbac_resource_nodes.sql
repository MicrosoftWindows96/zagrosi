-- rbac 001 — resource registry + org permission versions.
--
-- `resource_nodes` is the scope tree the resolution engine walks
-- (org > workspace > project > service > record); `org_permission_versions`
-- is the per-org monotonic counter the caches key their floors off.
--
-- FKs to identity-owned `orgs` are intentional (single database); only
-- Rust-type coupling between the crates is forbidden. FKs are declared
-- without ON DELETE CASCADE because the application layer handles
-- soft-delete cascade (matches identity's convention).
--
-- RLS: both tables are pattern P1 via the section-05 generator
-- (`zagrosi_enable_rls`, identity migration 022). FORCE matters because
-- `zagrosi_migrate` owns the tables.
--
-- Grants: identity migration 024's ALTER DEFAULT PRIVILEGES gives
-- `zagrosi_app` full DML on every future table as a safety net, so this
-- migration REVOKEs first and re-grants exactly the matrix verbs —
-- soft-delete-everywhere means `zagrosi_app` holds no DELETE here.

CREATE TABLE resource_nodes (
    id          UUID PRIMARY KEY,             -- UUIDv7, app-side
    org_id      UUID NOT NULL REFERENCES orgs (id),
    scope_type  TEXT NOT NULL CHECK (scope_type IN ('org','workspace','project','service','record')),
    parent_id   UUID NULL REFERENCES resource_nodes (id),
    external_id UUID NULL,                    -- the domain row this node mirrors
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ NULL,
    -- Org root <=> no parent; every non-org node hangs off a parent.
    CONSTRAINT resource_nodes_org_iff_rootless
        CHECK ((scope_type = 'org') = (parent_id IS NULL)),
    -- Composite target for org-pinned FKs (role_assignments.node_id):
    -- FK integrity checks bypass RLS, so referencing tables must pin
    -- the org alongside the id to keep cross-tenant references
    -- unrepresentable.
    CONSTRAINT resource_nodes_id_org_unique UNIQUE (id, org_id)
);

-- Exactly one live org root per org.
CREATE UNIQUE INDEX resource_nodes_org_root_unique_live
    ON resource_nodes (org_id)
    WHERE scope_type = 'org' AND deleted_at IS NULL;

-- Hot child-listing shape, org_id leading per the RLS catalog rule.
CREATE INDEX resource_nodes_org_parent_idx
    ON resource_nodes (org_id, parent_id)
    WHERE deleted_at IS NULL;

CREATE TABLE org_permission_versions (
    org_id  UUID PRIMARY KEY REFERENCES orgs (id),
    version BIGINT NOT NULL DEFAULT 1         -- row created by the org-root trigger
);

-- Stable scope ordering shared by the parent-validation trigger (and
-- readable by humans): lower level = wider scope.
CREATE FUNCTION zagrosi_rbac_scope_level(p_scope text) RETURNS integer
LANGUAGE sql IMMUTABLE
RETURN CASE p_scope
    WHEN 'org'       THEN 0
    WHEN 'workspace' THEN 1
    WHEN 'project'   THEN 2
    WHEN 'service'   THEN 3
    WHEN 'record'    THEN 4
END;

-- Parent validation: cross-row rules a CHECK cannot express. Plain
-- SECURITY INVOKER — an app-role insert cannot even see a cross-org
-- parent under RLS, so the lookup fails closed by construction; the
-- explicit org comparison below covers BYPASSRLS callers (backfills).
-- Depth <= 5 follows from the strictly-higher rule; no separate depth
-- check is needed. The service layer (section-09) re-validates for
-- friendlier errors.
CREATE FUNCTION zagrosi_rbac_validate_node_parent() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    parent_row resource_nodes%ROWTYPE;
BEGIN
    IF NEW.scope_type = 'org' THEN
        RETURN NEW;  -- parent_id IS NULL enforced by the CHECK constraint
    END IF;
    -- FOR SHARE closes the TOCTOU window: a concurrent soft-delete of
    -- the parent (an UPDATE, which the WHEN clause below deliberately
    -- does not re-validate) blocks until this insert commits, so a live
    -- child can never land under a tombstoned parent. Share locks are
    -- mutually compatible — concurrent child creations under one parent
    -- (the org root, typically) do not serialize each other.
    SELECT * INTO parent_row FROM resource_nodes WHERE id = NEW.parent_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'resource_nodes: parent % not found', NEW.parent_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF parent_row.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'resource_nodes: parent % is soft-deleted', NEW.parent_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF parent_row.org_id <> NEW.org_id THEN
        RAISE EXCEPTION 'resource_nodes: parent % belongs to a different org', NEW.parent_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    IF zagrosi_rbac_scope_level(parent_row.scope_type)
       >= zagrosi_rbac_scope_level(NEW.scope_type) THEN
        RAISE EXCEPTION
            'resource_nodes: parent scope % must be strictly higher than child scope %',
            parent_row.scope_type, NEW.scope_type
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER resource_nodes_validate_parent_insert
    BEFORE INSERT ON resource_nodes
    FOR EACH ROW EXECUTE FUNCTION zagrosi_rbac_validate_node_parent();

-- On UPDATE, only re-validate when the tree shape actually changes;
-- soft-delete cascades (bulk `SET deleted_at = now()`) must not trip
-- over parents tombstoned earlier in the same statement.
CREATE TRIGGER resource_nodes_validate_parent_update
    BEFORE UPDATE ON resource_nodes
    FOR EACH ROW
    WHEN (OLD.parent_id IS DISTINCT FROM NEW.parent_id
          OR OLD.org_id IS DISTINCT FROM NEW.org_id
          OR OLD.scope_type IS DISTINCT FROM NEW.scope_type)
    EXECUTE FUNCTION zagrosi_rbac_validate_node_parent();

-- Tenant isolation (P1) + verb matrix.
SELECT zagrosi_enable_rls('resource_nodes', 'p1');
SELECT zagrosi_enable_rls('org_permission_versions', 'p1');

REVOKE ALL ON resource_nodes FROM zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT SELECT, INSERT, UPDATE ON resource_nodes TO zagrosi_app;
GRANT SELECT ON resource_nodes TO zagrosi_maintenance;

REVOKE ALL ON org_permission_versions FROM zagrosi_app, zagrosi_auth, zagrosi_maintenance;
GRANT SELECT, UPDATE ON org_permission_versions TO zagrosi_app;
GRANT SELECT ON org_permission_versions TO zagrosi_maintenance;
