-- 007 — password_resets + email_verifications (paired migration).
--
-- Both tables follow the same shape: a token-hash row that is
-- single-use (enforced by a partial unique index on `token_hash`
-- where `used_at IS NULL`). Once consumed, the row stays for audit
-- but no longer occupies the unique slot.
--
-- `password_resets` token prefix `rst_*`; `email_verifications`
-- token prefix `vrf_*`. Prefix validation is enforced app-side
-- (the persistence layer + the password-auth surface).

CREATE TABLE password_resets (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id),
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ NULL,
    CONSTRAINT password_resets_expires_after_created
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX password_resets_token_hash_unique_unused
    ON password_resets (token_hash)
    WHERE used_at IS NULL;

CREATE INDEX password_resets_user_id_idx ON password_resets (user_id);

CREATE TABLE email_verifications (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id),
    email       TEXT NOT NULL,
    token_hash  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ NULL,
    CONSTRAINT email_verifications_expires_after_created
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX email_verifications_token_hash_unique_unused
    ON email_verifications (token_hash)
    WHERE used_at IS NULL;

CREATE INDEX email_verifications_user_id_idx ON email_verifications (user_id);
