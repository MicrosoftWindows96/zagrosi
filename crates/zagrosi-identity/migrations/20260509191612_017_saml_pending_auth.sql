-- 017 — saml_pending_auth.
--
-- SP-initiated AuthnRequest tracking. Mirrors the oidc_pending_auth
-- pattern from migration 011: persists the AuthnRequest ID and a
-- 256-bit RelayState alongside the resolving org_idp so the ACS
-- handler can correlate the IdP response to the original start
-- request. The partial unique index on `(org_idp_id, request_id)`
-- WHERE used_at IS NULL gives the ACS handler the same single-use
-- guarantee oidc_pending_auth provides — re-presentation of a used
-- AuthnRequest ID is rejected before the ACS strict-order pipeline
-- even fires.
--
-- The 10-minute TTL is enforced by the SAML SP at use time
-- (`expires_at < now() => reject`). A lightweight cleanup sweep
-- prunes both expired and used rows on a periodic worker. The
-- expiry index supports the sweep without scanning the whole table.

CREATE TABLE saml_pending_auth (
    id           UUID PRIMARY KEY,
    request_id   TEXT NOT NULL,
    relay_state  TEXT NOT NULL,
    org_idp_id   UUID NOT NULL REFERENCES org_idps (id),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at      TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX saml_pending_auth_request_id_unused
    ON saml_pending_auth (org_idp_id, request_id)
    WHERE used_at IS NULL;

CREATE INDEX saml_pending_auth_expires_at
    ON saml_pending_auth (expires_at);
