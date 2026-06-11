-- rbac 003 — org-root provisioning trigger on identity's `orgs`.
--
-- DOCUMENTED OWNERSHIP-RULE EXCEPTION: this rbac migration creates a
-- trigger on identity-owned `orgs` because the trigger writes rbac-owned
-- rows; identity's migration set is guaranteed to run first, so `orgs`
-- exists. The trigger keeps "every org has a root node + version row"
-- true forever, with zero identity-crate code knowing rbac exists.
--
-- SECURITY DEFINER rationale (pinned by tests): org creation happens
-- during sign-up BEFORE any `app.org_id` GUC exists, as `zagrosi_app`.
-- The function is created by the migration connection (`zagrosi_migrate`,
-- BYPASSRLS, table owner) and therefore runs as it, bypassing the P1
-- WITH CHECK that would otherwise reject the GUC-less inserts. The
-- pinned search_path is mandatory for SECURITY DEFINER.
--
-- `uuidv7()` is Postgres 18 native — the one documented exception to
-- app-side UUID generation (the trigger runs in-database; there is no
-- app-side code path to generate the id).

CREATE FUNCTION zagrosi_rbac_provision_org_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- Orgs inserted already-tombstoned (import/restore paths) get no
    -- live root; re-provisioning on restore is that flow's concern.
    IF NEW.deleted_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    INSERT INTO resource_nodes (id, org_id, scope_type, parent_id)
    VALUES (uuidv7(), NEW.id, 'org', NULL);
    INSERT INTO org_permission_versions (org_id) VALUES (NEW.id);
    RETURN NEW;
END $$;

CREATE TRIGGER org_root_provision AFTER INSERT ON orgs
    FOR EACH ROW EXECUTE FUNCTION zagrosi_rbac_provision_org_root();
