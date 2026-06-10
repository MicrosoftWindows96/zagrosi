-- 022 — RLS policy generator: zagrosi_enable_rls(table, pattern).
--
-- The single vocabulary every migration set (identity here; rbac/audit in
-- their own sets) uses to apply tenant-isolation policies. Owned by
-- `zagrosi_migrate` (this set runs as that role).
--
-- Non-negotiable properties:
--   * Every emitted policy names its target role explicitly
--     (`TO zagrosi_app`). Under FORCE ROW LEVEL SECURITY, roles without a
--     policy are default-denied — the intended posture for any
--     unanticipated role.
--   * Org/user comparisons use the fail-closed, InitPlan-friendly form: a
--     scalar subquery evaluated once per statement, with
--     NULLIF(current_setting(..., true), '') so a missing OR empty GUC
--     yields NULL and matches nothing.
--
-- Pattern vocabulary (P4 defined now; first consumed by the audit set):
--   p1  standard tenanted table: all four verbs bound to the org GUC.
--   p2  org-or-self: SELECT additionally matches `user_id = app.user_id`;
--       writes are org-only (the self-arm must never authorize writes —
--       a forged app.user_id must not enable cross-org mutation).
--   p3  nullable-org: rows with org_id IS NULL are platform-scoped and
--       visible/writable to every org context AND to no-context callers
--       (pre-login paths); org-attributed rows bind to the org GUC.
--   p4  append-only: INSERT (nullable-org check) + SELECT (org-bound);
--       deliberately NO UPDATE/DELETE policies — under FORCE, those verbs
--       are denied outright for zagrosi_app.
--
-- P5 ("excluded") means: do not call this function; the table must appear
-- in the machine-readable exclusion catalog
-- (zagrosi-test-support::rls_catalog) with a rationale.
--
-- Known limitation (full threat-model row lands with the docs section):
-- PK/unique/FK constraint checks bypass RLS (Postgres semantics), so
-- cross-tenant *existence* can leak via constraint errors. Mitigations:
-- UUIDv7 keys are unguessable, and unique constraints on tenanted tables
-- include org_id.

CREATE FUNCTION zagrosi_enable_rls(p_table text, p_pattern text)
RETURNS void
LANGUAGE plpgsql
AS $fn$
DECLARE
  org_pred  CONSTANT text :=
    $q$(SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)$q$;
  user_pred CONSTANT text :=
    $q$(SELECT NULLIF(current_setting('app.user_id', true), '')::uuid)$q$;
BEGIN
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', p_table);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', p_table);

  IF p_pattern = 'p1' THEN
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT TO zagrosi_app USING (org_id = %s)',
      p_table || '_app_select', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR INSERT TO zagrosi_app WITH CHECK (org_id = %s)',
      p_table || '_app_insert', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR UPDATE TO zagrosi_app USING (org_id = %s) WITH CHECK (org_id = %s)',
      p_table || '_app_update', p_table, org_pred, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR DELETE TO zagrosi_app USING (org_id = %s)',
      p_table || '_app_delete', p_table, org_pred);

  ELSIF p_pattern = 'p2' THEN
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT TO zagrosi_app USING (org_id = %s OR user_id = %s)',
      p_table || '_app_select', p_table, org_pred, user_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR INSERT TO zagrosi_app WITH CHECK (org_id = %s)',
      p_table || '_app_insert', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR UPDATE TO zagrosi_app USING (org_id = %s) WITH CHECK (org_id = %s)',
      p_table || '_app_update', p_table, org_pred, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR DELETE TO zagrosi_app USING (org_id = %s)',
      p_table || '_app_delete', p_table, org_pred);

  ELSIF p_pattern = 'p3' THEN
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT TO zagrosi_app USING (org_id IS NULL OR org_id = %s)',
      p_table || '_app_select', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR INSERT TO zagrosi_app WITH CHECK (org_id IS NULL OR org_id = %s)',
      p_table || '_app_insert', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR UPDATE TO zagrosi_app USING (org_id IS NULL OR org_id = %s) WITH CHECK (org_id IS NULL OR org_id = %s)',
      p_table || '_app_update', p_table, org_pred, org_pred);
    -- DELETE deliberately has NO nullable arm: platform-scoped rows
    -- (e.g. lockout aggregates) must not be deletable by arbitrary
    -- tenant contexts; their lifecycle belongs to the maintenance role.
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR DELETE TO zagrosi_app USING (org_id = %s)',
      p_table || '_app_delete', p_table, org_pred);

  ELSIF p_pattern = 'p4' THEN
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR INSERT TO zagrosi_app WITH CHECK (org_id IS NULL OR org_id = %s)',
      p_table || '_app_insert', p_table, org_pred);
    EXECUTE format(
      'CREATE POLICY %I ON %I FOR SELECT TO zagrosi_app USING (org_id = %s)',
      p_table || '_app_select', p_table, org_pred);
    -- Deliberately no UPDATE/DELETE policies: append-only under FORCE.

  ELSE
    RAISE EXCEPTION
      'zagrosi_enable_rls: unknown pattern "%" for table "%" (expected p1|p2|p3|p4)',
      p_pattern, p_table;
  END IF;
END;
$fn$;
