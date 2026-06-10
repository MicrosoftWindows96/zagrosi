-- 024 — explicit GRANT matrix for the runtime roles.
--
-- RLS does row filtering; grants do verb filtering. Every grant is
-- explicit and per-table — the ALTER DEFAULT PRIVILEGES at the end is a
-- safety net for future tables, not the mechanism (each future migration
-- still states its grants).
--
-- Schema USAGE + database CONNECT are bootstrap-owned (the public schema
-- is not owned by zagrosi_migrate, so they cannot be granted here; the
-- superuser bootstrap — test harness, compose initdb, managed-PG snippet —
-- grants them).
--
-- zagrosi_maintenance holds BYPASSRLS, so grants are its ONLY gate: it
-- gets SELECT on the tenanted tables (retention/archival/export reads).
-- Its audit-table grants arrive with the audit migration set.

-- zagrosi_app: full DML on every identity table. The verb-restricted
-- table (audit_events: INSERT+SELECT only) belongs to the audit set.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    orgs,
    users,
    user_org_memberships,
    sessions,
    api_tokens,
    password_resets,
    email_verifications,
    org_idps,
    org_idp_domains,
    scim_tokens,
    email_outbox,
    oidc_pending_auth,
    oidc_refresh_tokens,
    saml_assertion_replay,
    federated_identities,
    failed_signin_aggregates,
    service_tokens,
    saml_pending_auth,
    groups,
    group_memberships
TO zagrosi_app;

-- zagrosi_auth: SELECT only, on exactly the pre-tenant-context lookup
-- set — the bearer/cookie-hash introspection tables, the user row the
-- session introspector joins for password_updated_at/active checks, and
-- the SSO discovery pair (email domain -> IdP route happens before any
-- org is known; the domain is the public anchor).
GRANT SELECT ON
    sessions,
    users,
    api_tokens,
    scim_tokens,
    oidc_refresh_tokens,
    service_tokens
TO zagrosi_auth;
-- Discovery pair: column-scoped — the route decision needs identity/
-- protocol/priority columns only, never the IdP `config` envelope or a
-- pending domain's `challenge_token`.
GRANT SELECT (id, org_id, protocol, display_name, enabled, deleted_at)
    ON org_idps TO zagrosi_auth;
GRANT SELECT (id, org_idp_id, org_id, domain, priority, verified_at, deleted_at)
    ON org_idp_domains TO zagrosi_auth;

-- zagrosi_maintenance: SELECT on the tenanted identity tables.
GRANT SELECT ON
    user_org_memberships,
    api_tokens,
    scim_tokens,
    org_idps,
    org_idp_domains,
    groups,
    group_memberships,
    failed_signin_aggregates
TO zagrosi_maintenance;

-- Safety net for future tables created by zagrosi_migrate (self-FOR ROLE
-- needs no superuser). Future migrations still grant explicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE zagrosi_migrate IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO zagrosi_app;
ALTER DEFAULT PRIVILEGES FOR ROLE zagrosi_migrate IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO zagrosi_app;
