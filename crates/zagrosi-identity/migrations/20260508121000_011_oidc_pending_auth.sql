-- 011 — oidc_pending_auth.
--
-- Pending OIDC authorisation requests waiting for the IdP callback.
-- `state` and `nonce` carry 128-bit entropy values issued by the
-- gateway; `verifier_hash` is SHA-256 of the PKCE code verifier (the
-- raw verifier never persists). `csrf_cookie_value` is bound to the
-- `__Host-zagrosi_oidc_csrf` cookie. The partial unique on `state`
-- (where `used_at IS NULL`) enforces single-use redemption.

-- Every secret column on this table is stored as a SHA-256 hash, mirroring
-- the BYTEA-hash pattern used across sessions / api_tokens / scim_tokens /
-- oidc_refresh_tokens / password_resets / email_verifications. The OIDC
-- gateway computes the hashes when issuing the auth-request and again on
-- the callback, comparing only hashes. Raw `state`, `nonce`, and the CSRF
-- cookie value never persist.
CREATE TABLE oidc_pending_auth (
    id                 UUID PRIMARY KEY,
    org_idp_id         UUID NOT NULL REFERENCES org_idps (id),
    state_hash         BYTEA NOT NULL,
    nonce_hash         BYTEA NOT NULL,
    verifier_hash      BYTEA NOT NULL,
    csrf_cookie_hash   BYTEA NOT NULL,
    redirect_uri       TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ NOT NULL,
    used_at            TIMESTAMPTZ NULL,
    CONSTRAINT oidc_pending_auth_expires_after_created
        CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX oidc_pending_auth_state_hash_unique_unused
    ON oidc_pending_auth (state_hash)
    WHERE used_at IS NULL;

CREATE INDEX oidc_pending_auth_expires_at_idx
    ON oidc_pending_auth (expires_at);
