-- 008 — org_idps + org_idp_domains (paired migration).
--
-- `org_idps` is the per-org OIDC/SAML IdP configuration. `config` is
-- a JSONB blob versioned by `config_version` so the schema can evolve
-- (`OidcConfigV1` / `SamlConfigV1` ports live in zagrosi-core).
-- `is_default` flags the IdP that handles unrouted traffic for the
-- org; `enabled` is a kill-switch.
--
-- `org_idp_domains` carries the verified-domain → IdP mapping that
-- the multi-IdP routing layer consults when a user signs in. The
-- partial unique index on `(lower(domain), org_idp_id)` only counts
-- *verified* live rows, so unverified placeholders never block a
-- different IdP from claiming the same domain.

CREATE TABLE org_idps (
    id                UUID PRIMARY KEY,
    org_id            UUID NOT NULL REFERENCES orgs (id),
    protocol          TEXT NOT NULL CHECK (protocol IN ('oidc','saml')),
    display_name      TEXT NOT NULL,
    config            JSONB NOT NULL,
    config_version    SMALLINT NOT NULL DEFAULT 1,
    jit_provisioning  BOOLEAN NOT NULL DEFAULT TRUE,
    is_default        BOOLEAN NOT NULL DEFAULT FALSE,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at        TIMESTAMPTZ NULL
);

CREATE INDEX org_idps_org_id_idx ON org_idps (org_id);

CREATE TABLE org_idp_domains (
    id                 UUID PRIMARY KEY,
    org_idp_id         UUID NOT NULL REFERENCES org_idps (id),
    domain             TEXT NOT NULL,
    verified_at        TIMESTAMPTZ NULL,
    last_verified_via  TEXT NULL,
    priority           INT NOT NULL DEFAULT 100,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at         TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX org_idp_domains_lower_domain_unique_verified
    ON org_idp_domains (lower(domain), org_idp_id)
    WHERE verified_at IS NOT NULL AND deleted_at IS NULL;

-- Routing lookup (the multi-IdP routing layer) only ever considers verified, non-soft-deleted
-- rows; making the index partial keeps it small and aligned with the
-- partial-uniqueness above.
CREATE INDEX org_idp_domains_routing_idx
    ON org_idp_domains (lower(domain), priority)
    WHERE verified_at IS NOT NULL AND deleted_at IS NULL;
