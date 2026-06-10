-- 025 — apply tenant-isolation policies to the identity tables.
--
-- Pattern assignments come from the unit's authoritative per-table
-- catalog (mirrored machine-readably in
-- zagrosi-test-support::rls_catalog, which the completeness test and the
-- isolation property suites iterate). P5 entries are listed at the bottom
-- with their rationale: they are deliberately NOT RLS-enabled, each for a
-- pre-tenant-context reason, and remain protected by grants + app-layer
-- OrgScoped anchoring.
--
-- DEVIATION FROM THE DRAFT PLAN (documented): the plan listed
-- oidc_refresh_tokens as P1, but the table has no org_id column — it is
-- session-keyed and hash-addressed, and its rotation path runs BEFORE any
-- tenant context exists (exactly the sessions rationale). It is therefore
-- P5 with the sessions justification; org is reachable only via the
-- sessions join. Revisit if the table ever gains an org column.
--
-- zagrosi_auth: SELECT-only USING (true) policies on the P1 token tables
-- whose hash lookups happen pre-tenant-context (mechanism (a) of the
-- plan's §5.5 — simpler than SECURITY DEFINER functions under sqlx).
-- Hash unguessability (32-byte tokens) is the lookup guard; the role
-- cannot write anything anywhere (no INSERT/UPDATE/DELETE grants).

SELECT zagrosi_enable_rls('api_tokens', 'p1');
SELECT zagrosi_enable_rls('scim_tokens', 'p1');
SELECT zagrosi_enable_rls('org_idps', 'p1');
SELECT zagrosi_enable_rls('org_idp_domains', 'p1');
SELECT zagrosi_enable_rls('groups', 'p1');
SELECT zagrosi_enable_rls('group_memberships', 'p1');
SELECT zagrosi_enable_rls('user_org_memberships', 'p2');
SELECT zagrosi_enable_rls('failed_signin_aggregates', 'p3');

-- Pre-auth lookups for the auth role (see header): bearer-hash
-- introspection on the token tables, plus SSO discovery (email domain ->
-- IdP route) on the routing pair — both run before any org is known.
CREATE POLICY api_tokens_auth_select ON api_tokens
    FOR SELECT TO zagrosi_auth USING (true);
CREATE POLICY scim_tokens_auth_select ON scim_tokens
    FOR SELECT TO zagrosi_auth USING (true);
-- Row-scoped (not USING (true)): discovery only ever needs live,
-- enabled IdPs and live, VERIFIED domain claims.
CREATE POLICY org_idps_auth_select ON org_idps
    FOR SELECT TO zagrosi_auth USING (enabled AND deleted_at IS NULL);
CREATE POLICY org_idp_domains_auth_select ON org_idp_domains
    FOR SELECT TO zagrosi_auth
    USING (verified_at IS NOT NULL AND deleted_at IS NULL);

-- P5 exclusions (no RLS; rationale; mirrored in the Rust catalog):
--   users                    user-scoped; sign-in-by-email happens pre-context
--   orgs                     tenancy root; created pre-context during sign-up
--   sessions                 hash lookups pre-context (auth-role reads)
--   oidc_refresh_tokens      hash-addressed rotation pre-context; no org column
--   email_outbox             no org column; background-drained
--   password_resets          user-scoped single-use token table
--   email_verifications      user-scoped single-use token table
--   oidc_pending_auth        pre-auth flow state
--   saml_pending_auth        pre-auth flow state
--   saml_assertion_replay    replay ledger written mid-authentication
--   federated_identities     (protocol, issuer, subject) anchor lookup
--                            pre-context; org reachable via org_idp_id join
--   service_tokens           platform-internal principals
--   _sqlx_migrations         infra: migration bookkeeping, migrate-role only
