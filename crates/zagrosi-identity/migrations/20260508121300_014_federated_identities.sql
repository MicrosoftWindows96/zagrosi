-- 014 — federated_identities.
--
-- Canonical SSO anchor: `(protocol, issuer_or_entity_id,
-- subject_or_nameid)` is the unique key. Email is intentionally not
-- an SSO key. `user_id` is nullable to support tombstoning when the
-- linked user is soft-deleted (the persistence-layer cascade rules); the
-- tombstone still occupies the unique slot to prevent silent
-- re-attachment without an explicit admin merge.

CREATE TABLE federated_identities (
    id                    UUID PRIMARY KEY,
    protocol              TEXT NOT NULL CHECK (protocol IN ('oidc','saml')),
    issuer_or_entity_id   TEXT NOT NULL,
    subject_or_nameid     TEXT NOT NULL,
    org_idp_id            UUID NOT NULL REFERENCES org_idps (id),
    user_id               UUID NULL REFERENCES users (id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at         TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX federated_identities_anchor_unique
    ON federated_identities (protocol, issuer_or_entity_id, subject_or_nameid);

CREATE INDEX federated_identities_user_id_idx ON federated_identities (user_id);
CREATE INDEX federated_identities_org_idp_id_idx ON federated_identities (org_idp_id);
