// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRANT matrix (identity migration 024): app full DML, auth SELECT-only
//! on the lookup set, default privileges covering future tables.

use serial_test::serial;
use zagrosi_test_support::{TestDb, rls_catalog};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

async fn has_priv(
    db: &TestDb,
    role: &str,
    table: &str,
    privilege: &str,
) -> Result<bool, TestError> {
    Ok(sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(db.migrate_pool())
        .await?)
}

#[tokio::test]
#[serial]
async fn app_role_grants_match_catalog() -> TestResult {
    let db = TestDb::new().await?;
    // The catalog's `app_verbs` is the machine-readable grant matrix:
    // identity tables carry full DML; rbac tables are verb-restricted
    // (soft-delete-everywhere: no DELETE except hard-replaced entry
    // sets); infra bookkeeping grants zagrosi_app nothing. Assert both
    // directions so a stray grant fails as loudly as a missing one.
    for entry in rls_catalog() {
        for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
            let want = entry.app_verbs.contains(&privilege);
            assert_eq!(
                has_priv(&db, "zagrosi_app", entry.table, privilege).await?,
                want,
                "zagrosi_app {privilege} on {} must be {}",
                entry.table,
                if want { "granted" } else { "absent" }
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn auth_role_grants_are_select_only_on_lookup_tables() -> TestResult {
    let db = TestDb::new().await?;
    let lookup_set = [
        "sessions",
        "users",
        "api_tokens",
        "scim_tokens",
        "oidc_refresh_tokens",
        "service_tokens",
    ];
    for table in lookup_set {
        assert!(
            has_priv(&db, "zagrosi_auth", table, "SELECT").await?,
            "zagrosi_auth missing SELECT on {table}"
        );
    }
    // SSO discovery pair: COLUMN-scoped SELECT only (route-decision
    // columns; never the IdP `config` envelope / `challenge_token`).
    for table in ["org_idps", "org_idp_domains"] {
        let any_col: bool =
            sqlx::query_scalar("SELECT has_any_column_privilege('zagrosi_auth', $1, 'SELECT')")
                .bind(table)
                .fetch_one(db.migrate_pool())
                .await?;
        assert!(any_col, "zagrosi_auth missing column SELECT on {table}");
        assert!(
            !has_priv(&db, "zagrosi_auth", table, "SELECT").await?,
            "zagrosi_auth must NOT hold table-wide SELECT on {table}"
        );
    }
    let secret_cols: bool = sqlx::query_scalar(
        "SELECT has_column_privilege('zagrosi_auth', 'org_idps', 'config', 'SELECT')
             OR has_column_privilege('zagrosi_auth', 'org_idp_domains', 'challenge_token', 'SELECT')",
    )
    .fetch_one(db.migrate_pool())
    .await?;
    assert!(
        !secret_cols,
        "discovery grants must exclude config / challenge_token"
    );
    // No write verb anywhere; no SELECT outside the lookup set.
    for entry in rls_catalog() {
        if entry.table.starts_with('_') {
            continue;
        }
        for privilege in ["INSERT", "UPDATE", "DELETE"] {
            assert!(
                !has_priv(&db, "zagrosi_auth", entry.table, privilege).await?,
                "zagrosi_auth must never hold {privilege} (found on {})",
                entry.table
            );
        }
        if !lookup_set.contains(&entry.table) {
            // (The discovery pair holds column-scoped SELECT, which
            // has_table_privilege correctly reports as false.)
            assert!(
                !has_priv(&db, "zagrosi_auth", entry.table, "SELECT").await?,
                "zagrosi_auth table-wide SELECT leaked onto {}",
                entry.table
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn default_privileges_cover_future_tables() -> TestResult {
    let db = TestDb::new().await?;
    // As zagrosi_migrate, create a scratch table: ALTER DEFAULT
    // PRIVILEGES must have given zagrosi_app the baseline grants
    // automatically.
    sqlx::query("CREATE TABLE rls_default_priv_scratch (id UUID PRIMARY KEY)")
        .execute(db.migrate_pool())
        .await?;
    for privilege in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        assert!(
            has_priv(&db, "zagrosi_app", "rls_default_priv_scratch", privilege).await?,
            "default privileges missing {privilege}"
        );
    }
    sqlx::query("DROP TABLE rls_default_priv_scratch")
        .execute(db.migrate_pool())
        .await?;
    Ok(())
}
