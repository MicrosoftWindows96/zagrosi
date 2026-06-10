-- 023 — denormalize org_id onto group_memberships + org_idp_domains.
--
-- Both tables are genuinely tenant-owned but carried tenancy only via a
-- parent FK (groups.org_id / org_idps.org_id). RLS pattern P1 compares an
-- on-row org_id, so each gains the column (review-H2 precedent: add,
-- backfill from the parent, SET NOT NULL). Empty pre-release datasets make
-- the backfill trivially safe; on populated databases the UPDATE is a
-- single pass.

-- Composite uniques on the parents let the children carry composite
-- FKs binding the denormalized org_id to the PARENT's org — without
-- them an app-role insert under its own org GUC could attach a row to
-- a foreign parent with a lying org_id (FK checks bypass RLS).
ALTER TABLE groups
    ADD CONSTRAINT groups_id_org_unique UNIQUE (id, org_id);
ALTER TABLE org_idps
    ADD CONSTRAINT org_idps_id_org_unique UNIQUE (id, org_id);

ALTER TABLE group_memberships
    ADD COLUMN org_id UUID NULL REFERENCES orgs (id);

UPDATE group_memberships gm
SET org_id = g.org_id
FROM groups g
WHERE gm.group_id = g.id
  AND gm.org_id IS NULL;

ALTER TABLE group_memberships
    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE group_memberships
    ADD CONSTRAINT group_memberships_group_org_fk
        FOREIGN KEY (group_id, org_id) REFERENCES groups (id, org_id);

CREATE INDEX group_memberships_org_id_idx
    ON group_memberships (org_id)
    WHERE deleted_at IS NULL;

ALTER TABLE org_idp_domains
    ADD COLUMN org_id UUID NULL REFERENCES orgs (id);

UPDATE org_idp_domains d
SET org_id = i.org_id
FROM org_idps i
WHERE d.org_idp_id = i.id
  AND d.org_id IS NULL;

ALTER TABLE org_idp_domains
    ALTER COLUMN org_id SET NOT NULL;
ALTER TABLE org_idp_domains
    ADD CONSTRAINT org_idp_domains_idp_org_fk
        FOREIGN KEY (org_idp_id, org_id) REFERENCES org_idps (id, org_id);

CREATE INDEX org_idp_domains_org_id_idx
    ON org_idp_domains (org_id)
    WHERE deleted_at IS NULL;
