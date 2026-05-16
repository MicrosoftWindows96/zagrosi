-- 012 — oidc_refresh_tokens.
--
-- Refresh-token chain for OIDC sessions. `prev_id` self-references
-- the previous refresh token in the chain so replay-detection can
-- revoke the entire chain when a re-use is observed (the OIDC client).
-- `token_hash` is SHA-256 of the raw refresh-token value.

CREATE TABLE oidc_refresh_tokens (
    id          UUID PRIMARY KEY,
    session_id  UUID NOT NULL REFERENCES sessions (id),
    token_hash  BYTEA NOT NULL,
    prev_id     UUID NULL REFERENCES oidc_refresh_tokens (id),
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ NULL,
    revoked_at  TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX oidc_refresh_tokens_token_hash_unique_live
    ON oidc_refresh_tokens (token_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX oidc_refresh_tokens_session_idx ON oidc_refresh_tokens (session_id);
