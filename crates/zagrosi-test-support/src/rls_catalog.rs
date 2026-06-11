// SPDX-License-Identifier: AGPL-3.0-or-later

//! Machine-readable RLS catalog.
//!
//! The single source of truth shared by the completeness test (every
//! `public` table must be policy-covered, P5-listed, or infra-excluded),
//! the isolation property suites (which iterate every P1/P2/P3 entry via
//! its registered seeder), and the future documentation generator.
//!
//! Sections appending tables (rbac, audit, SIEM destinations) append
//! their entries — and seeders for tenanted tables — here. A tenanted
//! entry without a seeder fails the isolation suite loudly, keeping the
//! property tests auto-covering.

use std::future::Future;
use std::pin::Pin;

use sqlx::PgPool;
use uuid::Uuid;

/// RLS pattern assignment, mirroring the SQL generator's vocabulary
/// (`zagrosi_enable_rls`, identity migration 022).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RlsPattern {
    /// Standard tenanted table: all four verbs bound to the org GUC.
    P1Standard,
    /// Org-or-self: SELECT also matches `user_id = app.user_id`;
    /// writes are org-only.
    P2OrgOrSelf,
    /// Nullable-org: `org_id IS NULL` rows are platform-scoped.
    P3NullableOrg,
    /// Append-only: INSERT + SELECT policies, no UPDATE/DELETE.
    P4AppendOnly,
    /// Deliberately excluded from RLS, with a pre-tenant-context
    /// rationale; protected by grants + app-layer anchoring.
    P5Excluded,
    /// Infrastructure bookkeeping (e.g. `_sqlx_migrations`).
    Infra,
}

/// Seeds minimal valid rows for one org via the migrate pool
/// (BYPASSRLS), so the isolation suites can compare visibility across
/// two orgs. `None` for P5/Infra entries.
pub type SeedFn =
    fn(&PgPool, Uuid) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>>;

/// `zagrosi_app` verb set for tables with full DML (the identity
/// baseline — RLS does row filtering, grants do verb filtering).
pub const APP_FULL_DML: &[&str] = &["SELECT", "INSERT", "UPDATE", "DELETE"];

/// `zagrosi_app` verb set for soft-delete tables: no DELETE — rows are
/// tombstoned via `deleted_at`, never removed (rbac convention).
pub const APP_SOFT_DELETE: &[&str] = &["SELECT", "INSERT", "UPDATE"];

/// One catalog row.
pub struct RlsCatalogEntry {
    /// Table name in schema `public`.
    pub table: &'static str,
    /// Pattern assignment.
    pub pattern: RlsPattern,
    /// Why the table has this pattern (verbatim from the section plan).
    pub rationale: &'static str,
    /// Two-org fixture seeder for the isolation proptests.
    pub seed: Option<SeedFn>,
    /// Exact `zagrosi_app` grant verbs — the machine-readable grant
    /// matrix the `rls_grants` suite asserts positively AND negatively.
    pub app_verbs: &'static [&'static str],
}

/// The authoritative catalog (identity tables; later sections append).
#[must_use]
#[allow(clippy::too_many_lines)] // one entry per table, deliberately exhaustive
pub fn rls_catalog() -> &'static [RlsCatalogEntry] {
    &[
        RlsCatalogEntry {
            table: "api_tokens",
            pattern: RlsPattern::P1Standard,
            rationale: "tenanted PATs; auth-path hash reads via zagrosi_auth USING(true) policy",
            seed: Some(seed_api_tokens),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "scim_tokens",
            pattern: RlsPattern::P1Standard,
            rationale: "tenanted SCIM bearers; auth-path hash reads via zagrosi_auth policy",
            seed: Some(seed_scim_tokens),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "org_idps",
            pattern: RlsPattern::P1Standard,
            rationale: "per-org IdP configuration; SSO-discovery reads via zagrosi_auth policy",
            seed: Some(seed_org_idps),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "org_idp_domains",
            pattern: RlsPattern::P1Standard,
            rationale: "per-org verified-domain claims (org_id denormalized in migration 023); \
                        SSO-discovery reads via zagrosi_auth policy",
            seed: Some(seed_org_idp_domains),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "groups",
            pattern: RlsPattern::P1Standard,
            rationale: "per-org SCIM groups",
            seed: Some(seed_groups),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "group_memberships",
            pattern: RlsPattern::P1Standard,
            rationale: "group join rows (org_id denormalized in migration 023)",
            seed: Some(seed_group_memberships),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "user_org_memberships",
            pattern: RlsPattern::P2OrgOrSelf,
            rationale: "org rows + SELECT-only self-arm (a user lists their own memberships \
                        across orgs before choosing one)",
            seed: Some(seed_user_org_memberships),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "failed_signin_aggregates",
            pattern: RlsPattern::P3NullableOrg,
            rationale: "org_id nullable by design: IP-only rows recorded pre-auth",
            seed: Some(seed_failed_signin_aggregates),
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "users",
            pattern: RlsPattern::P5Excluded,
            rationale: "user-scoped; sign-in-by-email lookups happen pre-tenant-context",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "orgs",
            pattern: RlsPattern::P5Excluded,
            rationale: "tenancy root; created pre-context during sign-up; PK/slug-addressed",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "sessions",
            pattern: RlsPattern::P5Excluded,
            rationale: "hash lookups pre-context (auth-role reads)",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "oidc_refresh_tokens",
            pattern: RlsPattern::P5Excluded,
            rationale: "hash-addressed rotation pre-context; no org column (plan deviation: \
                        drafted P1, but the table is session-keyed — sessions rationale)",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "email_outbox",
            pattern: RlsPattern::P5Excluded,
            rationale: "no org column; background-drained",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "password_resets",
            pattern: RlsPattern::P5Excluded,
            rationale: "user-scoped single-use token table",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "email_verifications",
            pattern: RlsPattern::P5Excluded,
            rationale: "user-scoped single-use token table",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "oidc_pending_auth",
            pattern: RlsPattern::P5Excluded,
            rationale: "pre-auth flow state",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "saml_pending_auth",
            pattern: RlsPattern::P5Excluded,
            rationale: "pre-auth flow state",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "saml_assertion_replay",
            pattern: RlsPattern::P5Excluded,
            rationale: "replay ledger written mid-authentication",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "federated_identities",
            pattern: RlsPattern::P5Excluded,
            rationale: "(protocol, issuer, subject) anchor lookup pre-context; org reachable \
                        only via org_idp_id join",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "service_tokens",
            pattern: RlsPattern::P5Excluded,
            rationale: "platform-internal principals",
            seed: None,
            app_verbs: APP_FULL_DML,
        },
        RlsCatalogEntry {
            table: "_sqlx_migrations",
            pattern: RlsPattern::Infra,
            rationale: "migration bookkeeping; migrate-role only",
            seed: None,
            app_verbs: &[],
        },
        // --- rbac set (section 06). Soft-delete-everywhere: zagrosi_app
        //     holds no DELETE except custom_role_entries (hard-replaced
        //     wholesale; no deleted_at column).
        RlsCatalogEntry {
            table: "resource_nodes",
            pattern: RlsPattern::P1Standard,
            rationale: "tenanted scope tree; org roots trigger-provisioned",
            seed: Some(seed_resource_nodes),
            app_verbs: APP_SOFT_DELETE,
        },
        RlsCatalogEntry {
            table: "org_permission_versions",
            pattern: RlsPattern::P1Standard,
            rationale: "per-org cache-version counter keyed directly on org_id; rows \
                        trigger-provisioned, app only reads/bumps",
            seed: Some(seed_org_permission_versions),
            app_verbs: &["SELECT", "UPDATE"],
        },
        RlsCatalogEntry {
            table: "custom_roles",
            pattern: RlsPattern::P1Standard,
            rationale: "tenanted custom role definitions",
            seed: Some(seed_custom_roles),
            app_verbs: APP_SOFT_DELETE,
        },
        RlsCatalogEntry {
            table: "custom_role_entries",
            pattern: RlsPattern::P1Standard,
            rationale: "capability entries (org_id denormalized, FK-pinned to the parent \
                        role's org); hard-replaced wholesale, hence app DELETE",
            seed: Some(seed_custom_role_entries),
            app_verbs: &["SELECT", "INSERT", "DELETE"],
        },
        RlsCatalogEntry {
            table: "role_assignments",
            pattern: RlsPattern::P1Standard,
            rationale: "tenanted user-to-role bindings on scope nodes",
            seed: Some(seed_role_assignments),
            app_verbs: APP_SOFT_DELETE,
        },
    ]
}

/// Insert a user row dedicated to a seeded fixture (unique email per call).
async fn seed_fixture_user(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(format!("rls-{id}@example.test"))
        .bind("rls fixture")
        .execute(pool)
        .await?;
    Ok(id)
}

fn seed_api_tokens(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let user = seed_fixture_user(pool).await?;
        sqlx::query(
            "INSERT INTO api_tokens (id, token_hash, user_id, org_id, display_name)
             VALUES ($1, $2, $3, $4, 'rls fixture')",
        )
        .bind(Uuid::now_v7())
        .bind(Uuid::now_v7().as_bytes().repeat(2))
        .bind(user)
        .bind(org)
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_scim_tokens(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        sqlx::query(
            "INSERT INTO scim_tokens (id, org_id, display_name, token_hash)
             VALUES ($1, $2, 'rls fixture', $3)",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .bind(Uuid::now_v7().as_bytes().repeat(2))
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_org_idps(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        insert_org_idp(pool, org).await?;
        Ok(())
    })
}

async fn insert_org_idp(pool: &PgPool, org: Uuid) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO org_idps (id, org_id, protocol, display_name, config)
         VALUES ($1, $2, 'oidc', $3, '{}'::jsonb)",
    )
    .bind(id)
    .bind(org)
    .bind(format!("rls fixture {id}"))
    .execute(pool)
    .await?;
    Ok(id)
}

fn seed_org_idp_domains(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let idp = insert_org_idp(pool, org).await?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO org_idp_domains (id, org_idp_id, org_id, domain)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(idp)
        .bind(org)
        .bind(format!("{}.example.test", id.simple()))
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_groups(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        insert_group(pool, org).await?;
        Ok(())
    })
}

async fn insert_group(pool: &PgPool, org: Uuid) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO groups (id, org_id, display_name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(org)
        .bind(format!("rls fixture {id}"))
        .execute(pool)
        .await?;
    Ok(id)
}

fn seed_group_memberships(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let group = insert_group(pool, org).await?;
        let user = seed_fixture_user(pool).await?;
        sqlx::query(
            "INSERT INTO group_memberships (id, group_id, user_id, org_id)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(Uuid::now_v7())
        .bind(group)
        .bind(user)
        .bind(org)
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_user_org_memberships(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let user = seed_fixture_user(pool).await?;
        sqlx::query(
            "INSERT INTO user_org_memberships (id, user_id, org_id, joined_via)
             VALUES ($1, $2, $3, 'manual')",
        )
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(org)
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_failed_signin_aggregates(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        sqlx::query(
            "INSERT INTO failed_signin_aggregates
                 (id, org_id, ip, window_start, count, first_attempt_at, last_attempt_at)
             VALUES ($1, $2, '203.0.113.7'::inet, now(), 1, now(), now())",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .execute(pool)
        .await?;
        Ok(())
    })
}

/// The org's live root node id. Errors (`RowNotFound`) when invisible —
/// which is exactly the fail-closed probe the no-GUC isolation test
/// wants when a seeder runs over the app pool without tenant context.
async fn org_root_node(pool: &PgPool, org: Uuid) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM resource_nodes
         WHERE org_id = $1 AND scope_type = 'org' AND deleted_at IS NULL",
    )
    .bind(org)
    .fetch_one(pool)
    .await
}

fn seed_resource_nodes(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let root = org_root_node(pool, org).await?;
        sqlx::query(
            "INSERT INTO resource_nodes (id, org_id, scope_type, parent_id)
             VALUES ($1, $2, 'workspace', $3)",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .bind(root)
        .execute(pool)
        .await?;
        Ok(())
    })
}

/// `org_permission_versions` is PK-per-org and trigger-provisioned, so
/// the seeder cannot INSERT; it bumps the existing row instead. Zero
/// rows affected (row invisible / absent) is reported as an error so
/// the fail-closed no-GUC probe still observes a refusal.
fn seed_org_permission_versions(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let affected = sqlx::query(
            "UPDATE org_permission_versions SET version = version + 1 WHERE org_id = $1",
        )
        .bind(org)
        .execute(pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(sqlx::Error::RowNotFound);
        }
        Ok(())
    })
}

fn seed_custom_roles(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        insert_custom_role(pool, org).await?;
        Ok(())
    })
}

async fn insert_custom_role(pool: &PgPool, org: Uuid) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO custom_roles (id, org_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(org)
        .bind(format!("rls fixture {id}"))
        .execute(pool)
        .await?;
    Ok(id)
}

fn seed_custom_role_entries(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let role = insert_custom_role(pool, org).await?;
        sqlx::query(
            "INSERT INTO custom_role_entries (id, custom_role_id, org_id, capability, effect)
             VALUES ($1, $2, $3, 'work_item.read', 'grant')",
        )
        .bind(Uuid::now_v7())
        .bind(role)
        .bind(org)
        .execute(pool)
        .await?;
        Ok(())
    })
}

fn seed_role_assignments(
    pool: &PgPool,
    org: Uuid,
) -> Pin<Box<dyn Future<Output = Result<(), sqlx::Error>> + Send + '_>> {
    Box::pin(async move {
        let user = seed_fixture_user(pool).await?;
        let root = org_root_node(pool, org).await?;
        sqlx::query(
            "INSERT INTO role_assignments
                 (id, org_id, user_id, builtin_role, node_id, created_by)
             VALUES ($1, $2, $3, 'member', $4, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(org)
        .bind(user)
        .bind(root)
        .execute(pool)
        .await?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenanted_entries_register_seeders() {
        for entry in rls_catalog() {
            let tenanted = matches!(
                entry.pattern,
                RlsPattern::P1Standard | RlsPattern::P2OrgOrSelf | RlsPattern::P3NullableOrg
            );
            assert_eq!(
                tenanted,
                entry.seed.is_some(),
                "catalog entry `{}` must register a seeder iff it is tenanted",
                entry.table
            );
            assert!(!entry.rationale.is_empty());
        }
    }

    #[test]
    fn catalog_has_no_duplicate_tables() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in rls_catalog() {
            assert!(
                seen.insert(entry.table),
                "duplicate entry `{}`",
                entry.table
            );
        }
    }

    #[test]
    fn app_verbs_are_well_formed() {
        for entry in rls_catalog() {
            for verb in entry.app_verbs {
                assert!(
                    APP_FULL_DML.contains(verb),
                    "catalog entry `{}` lists unknown verb `{verb}`",
                    entry.table
                );
            }
            if matches!(entry.pattern, RlsPattern::Infra) {
                assert!(
                    entry.app_verbs.is_empty(),
                    "infra entry `{}` must grant zagrosi_app nothing",
                    entry.table
                );
            }
        }
    }
}
