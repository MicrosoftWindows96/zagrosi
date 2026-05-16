-- 003 — users.
--
-- Canonical user table. UUID v7 ID generated app-side. Email is stored
-- case-preserving in `email`; `email_lower` is a generated column that
-- always equals `lower(email)` and is the column uniqueness + lookup
-- indices target. `password_hash` is NULLable to support SSO-only
-- accounts. `password_hash_version` tracks the Argon2id profile
-- version. `password_updated_at` is the password-reset revocation
-- invariant consumed by sessions.

CREATE TABLE users (
    id                     UUID PRIMARY KEY,
    email                  TEXT NOT NULL,
    email_lower            TEXT GENERATED ALWAYS AS (lower(email)) STORED,
    email_verified_at      TIMESTAMPTZ NULL,
    display_name           TEXT NOT NULL,
    password_hash          TEXT NULL,
    password_updated_at    TIMESTAMPTZ NULL,
    password_hash_version  SMALLINT NOT NULL DEFAULT 1,
    mfa_enrolled_at        TIMESTAMPTZ NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at             TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX users_email_lower_unique_live
    ON users (email_lower)
    WHERE deleted_at IS NULL;

CREATE INDEX users_deleted_at_idx ON users (deleted_at);
