-- 006 — api_tokens.
--
-- User-issued personal access tokens (`pat_*`). `token_hash` is
-- SHA-256(token); the prefix is validated app-side. `scopes` is a
-- TEXT array of authorisation scope strings consumed by future
-- policy code. `last_used_*` columns are best-effort observability.

CREATE TABLE api_tokens (
    id            UUID PRIMARY KEY,
    token_hash    BYTEA NOT NULL,
    user_id       UUID NOT NULL REFERENCES users (id),
    org_id        UUID NOT NULL REFERENCES orgs (id),
    display_name  TEXT NOT NULL,
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    last_used_at  TIMESTAMPTZ NULL,
    last_used_ip  INET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NULL,
    revoked_at    TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX api_tokens_token_hash_unique_live
    ON api_tokens (token_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX api_tokens_user_org_idx ON api_tokens (user_id, org_id);
