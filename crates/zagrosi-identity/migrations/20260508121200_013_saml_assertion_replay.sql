-- 013 — saml_assertion_replay.
--
-- SAML assertion replay-protection ledger. Composite PK on
-- `(org_idp_id, assertion_id)` IS the replay-rejection mechanism: a
-- duplicate insert raises a unique violation, which the SAML SP
-- translates into an authentication failure. Cleanup
-- sweeps prune rows past `not_on_or_after`.

CREATE TABLE saml_assertion_replay (
    org_idp_id       UUID NOT NULL REFERENCES org_idps (id),
    assertion_id     TEXT NOT NULL,
    not_on_or_after  TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_idp_id, assertion_id)
);

CREATE INDEX saml_assertion_replay_not_on_or_after_idx
    ON saml_assertion_replay (not_on_or_after);
