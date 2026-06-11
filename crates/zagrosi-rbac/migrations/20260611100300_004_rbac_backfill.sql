-- rbac 004 — backfill: roots + version rows for pre-existing orgs, and
-- legacy `basic_role` placeholders converted into real role assignments.
--
-- Runs as `zagrosi_migrate` (BYPASSRLS) — no per-org GUC loops needed.
-- `uuidv7()` here shares rbac 003's documented exception to app-side
-- UUID generation: the rows are minted in-database with no app code
-- path involved.
--
-- Role mapping (fixed): owner -> org_owner, admin -> org_admin,
-- member -> member, any other value -> member + WARNING per row.
-- Unit 02 verified: no shipped flow ever wrote 'owner' (sign-up creates
-- no membership; SCIM and SSO JIT write 'member' / a configured default),
-- so ownerless orgs are the expected legacy shape — each org's earliest
-- live membership (created_at, id tiebreak) is additionally promoted to
-- `org_owner`, keeping its mapped assignment intact (bindings are
-- additive; resolution unions grants).
--
-- Backfilled assignments are self-attributed: `created_by = user_id`
-- (there is no actor to credit for a migration-minted binding).
--
-- Assertion (documented deviation from the plan's blanket form): every
-- live org WITH at least one live membership must end with exactly one
-- live org-root `org_owner` assignment, or the migration fails. Live
-- orgs with ZERO live memberships cannot have an owner invented for
-- them — they get root + version rows and a WARNING (section-10's
-- signup flow assigns owners for every org created from then on). More
-- than one owner is impossible from unit-02 data (no 'owner' values
-- exist; memberships are unique per user+org) — tripping it means
-- hand-edited data, and failing loudly is intended.

-- 1. Root nodes for live orgs that predate the rbac 003 trigger.
INSERT INTO resource_nodes (id, org_id, scope_type, parent_id)
SELECT uuidv7(), o.id, 'org', NULL
FROM orgs o
WHERE o.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM resource_nodes rn
      WHERE rn.org_id = o.id AND rn.scope_type = 'org' AND rn.deleted_at IS NULL
  );

-- 2. Version rows for live orgs lacking one.
INSERT INTO org_permission_versions (org_id)
SELECT o.id
FROM orgs o
WHERE o.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM org_permission_versions v WHERE v.org_id = o.id
  );

-- 3a. Loud per-row warnings for unknown basic_role values (mapped to
--     'member' below).
DO $$
DECLARE
    m RECORD;
BEGIN
    FOR m IN
        SELECT uom.id, uom.basic_role
        FROM user_org_memberships uom
        JOIN orgs o ON o.id = uom.org_id AND o.deleted_at IS NULL
        WHERE uom.deleted_at IS NULL
          AND uom.basic_role NOT IN ('owner', 'admin', 'member')
    LOOP
        RAISE WARNING
            'rbac backfill: membership % has unknown basic_role "%" — mapping to member',
            m.id, m.basic_role;
    END LOOP;
END $$;

-- 3b. One org-root assignment per live membership of a live org.
--     (`user_org_memberships` is unique per live (user, org), so this
--     cannot collide with the live-binding partial unique.)
INSERT INTO role_assignments
    (id, org_id, user_id, builtin_role, custom_role_id, node_id, created_by)
SELECT
    uuidv7(),
    uom.org_id,
    uom.user_id,
    CASE uom.basic_role
        WHEN 'owner' THEN 'org_owner'
        WHEN 'admin' THEN 'org_admin'
        ELSE 'member'
    END,
    NULL,
    rn.id,
    uom.user_id
FROM user_org_memberships uom
JOIN orgs o ON o.id = uom.org_id AND o.deleted_at IS NULL
JOIN resource_nodes rn
    ON rn.org_id = uom.org_id AND rn.scope_type = 'org' AND rn.deleted_at IS NULL
WHERE uom.deleted_at IS NULL;

-- 4. Ownerless orgs: promote the earliest live membership to org_owner
--    (additional binding; the mapped one stays).
INSERT INTO role_assignments
    (id, org_id, user_id, builtin_role, custom_role_id, node_id, created_by)
SELECT uuidv7(), pick.org_id, pick.user_id, 'org_owner', NULL, rn.id, pick.user_id
FROM (
    SELECT DISTINCT ON (uom.org_id) uom.org_id, uom.user_id
    FROM user_org_memberships uom
    JOIN orgs o ON o.id = uom.org_id AND o.deleted_at IS NULL
    WHERE uom.deleted_at IS NULL
    ORDER BY uom.org_id, uom.created_at, uom.id
) pick
JOIN resource_nodes rn
    ON rn.org_id = pick.org_id AND rn.scope_type = 'org' AND rn.deleted_at IS NULL
WHERE NOT EXISTS (
    SELECT 1 FROM role_assignments ra
    WHERE ra.node_id = rn.id
      AND ra.builtin_role = 'org_owner'
      AND ra.deleted_at IS NULL
);

-- 5. Assertions: fail the migration on any org that ends up wrong.
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Every live org carries a live root and a version row.
    FOR r IN
        SELECT o.id
        FROM orgs o
        WHERE o.deleted_at IS NULL
          AND (NOT EXISTS (
                   SELECT 1 FROM resource_nodes rn
                   WHERE rn.org_id = o.id AND rn.scope_type = 'org'
                     AND rn.deleted_at IS NULL)
               OR NOT EXISTS (
                   SELECT 1 FROM org_permission_versions v WHERE v.org_id = o.id))
    LOOP
        RAISE EXCEPTION
            'rbac backfill: live org % is missing its root node or version row', r.id;
    END LOOP;

    -- Exactly one live org-root org_owner per live org with members.
    FOR r IN
        SELECT
            o.id AS org_id,
            count(ra.id) AS owner_count,
            EXISTS (
                SELECT 1 FROM user_org_memberships m
                WHERE m.org_id = o.id AND m.deleted_at IS NULL
            ) AS has_members
        FROM orgs o
        JOIN resource_nodes rn
            ON rn.org_id = o.id AND rn.scope_type = 'org' AND rn.deleted_at IS NULL
        LEFT JOIN role_assignments ra
            ON ra.node_id = rn.id
           AND ra.builtin_role = 'org_owner'
           AND ra.deleted_at IS NULL
        WHERE o.deleted_at IS NULL
        GROUP BY o.id
    LOOP
        IF r.has_members AND r.owner_count <> 1 THEN
            RAISE EXCEPTION
                'rbac backfill: live org % has % live org-root org_owner assignments (want exactly 1)',
                r.org_id, r.owner_count;
        ELSIF NOT r.has_members THEN
            RAISE WARNING
                'rbac backfill: live org % has no live memberships — ownerless after backfill',
                r.org_id;
        END IF;
    END LOOP;
END $$;

-- `user_org_memberships.basic_role` is retained but superseded from this
-- point: nothing in the rbac crate reads it, and identity's signup/JIT
-- flows start creating assignments directly in section-10.
