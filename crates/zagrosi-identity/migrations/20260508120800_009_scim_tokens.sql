-- 009 — scim_tokens.
--
-- Per-org SCIM bearer tokens (`scim_*`). `scopes` is the SCIM scope
-- set (`users:read`, `users:write`, `groups:read`, `groups:write`).
-- `allowed_cidrs` restricts SCIM connections by source IP; an empty
-- array means unrestricted. `tolerant_mode` toggles workarounds for
-- Entra ID PATCH deviations (the SCIM server).

CREATE TABLE scim_tokens (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs (id),
    display_name    TEXT NOT NULL,
    token_hash      BYTEA NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT ARRAY['users:read','users:write','groups:read','groups:write']::TEXT[],
    allowed_cidrs   INET[] NOT NULL DEFAULT '{}',
    tolerant_mode   BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at    TIMESTAMPTZ NULL,
    last_used_ip    INET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NULL,
    revoked_at      TIMESTAMPTZ NULL,
    deleted_at      TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX scim_tokens_token_hash_unique_live
    ON scim_tokens (token_hash)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;

CREATE INDEX scim_tokens_org_id_idx ON scim_tokens (org_id);
