-- 005 — sessions.
--
-- Browser session cookies (`sid_*`). `token_hash` is SHA-256 of the
-- raw cookie value; the raw value never lands in the database.
-- `version` is a monotonically increasing counter consumed by
-- optimistic locking when the active org switches.
-- `amr` (RFC 8176) and `acr` (RFC 6711 / OIDC Core) record the
-- authentication methods + assurance level for downstream policy.

CREATE TABLE sessions (
    id            UUID PRIMARY KEY,
    token_hash    BYTEA NOT NULL,
    user_id       UUID NOT NULL REFERENCES users (id),
    org_id        UUID NULL REFERENCES orgs (id),
    user_agent    TEXT NULL,
    ip_addr       INET NULL,
    version       BIGINT NOT NULL DEFAULT 1,
    amr           TEXT[] NOT NULL DEFAULT '{}',
    acr           TEXT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ NULL,
    deleted_at    TIMESTAMPTZ NULL,
    CONSTRAINT sessions_revoked_after_created
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX sessions_token_hash_unique_live
    ON sessions (token_hash)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;

CREATE INDEX sessions_user_expires_active_idx
    ON sessions (user_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_user_created_idx ON sessions (user_id, created_at);
