// SPDX-License-Identifier: AGPL-3.0-or-later

//! The catalog gate: every table in schema `public` must be RLS-covered,
//! P5-listed, or infra-excluded — driven from the shared machine-readable
//! catalog so any future migration adding an undecided table fails here.

use std::collections::BTreeSet;

use serial_test::serial;
use zagrosi_test_support::{RlsPattern, TestDb, rls_catalog};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[tokio::test]
#[serial]
async fn every_table_policy_covered_or_p5_listed() -> TestResult {
    let db = TestDb::new().await?;
    let tables: Vec<(String, bool, bool)> = sqlx::query_as(
        "SELECT c.relname::text, c.relrowsecurity, c.relforcerowsecurity
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind = 'r'
         ORDER BY c.relname",
    )
    .fetch_all(db.migrate_pool())
    .await?;

    let catalog: std::collections::BTreeMap<&str, &RlsPattern> = rls_catalog()
        .iter()
        .map(|e| (e.table, &e.pattern))
        .collect();

    for (table, rls_enabled, rls_forced) in &tables {
        // Infra exclusion: sqlx migration bookkeeping (incl. future
        // per-set history tables).
        if table.starts_with("_sqlx_migrations") {
            continue;
        }
        let pattern = catalog.get(table.as_str()).unwrap_or_else(|| {
            panic!(
                "table `{table}` has no RLS catalog entry — every new table \
                 must pick a pattern (P1-P4) or be P5-listed with a rationale"
            )
        });
        match pattern {
            RlsPattern::P1Standard
            | RlsPattern::P2OrgOrSelf
            | RlsPattern::P3NullableOrg
            | RlsPattern::P4AppendOnly => {
                assert!(
                    *rls_enabled && *rls_forced,
                    "table `{table}` is cataloged tenanted but not ENABLE+FORCE RLS"
                );
                let policies: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM pg_policies WHERE tablename = $1")
                        .bind(table)
                        .fetch_one(db.migrate_pool())
                        .await?;
                assert!(policies > 0, "table `{table}` has RLS but zero policies");
            }
            RlsPattern::P5Excluded | RlsPattern::Infra => {
                assert!(
                    !*rls_enabled,
                    "table `{table}` is P5/infra-listed but has RLS enabled — \
                     update the catalog or drop the policies"
                );
            }
        }
    }

    // Reverse direction: no stale catalog entries for dropped tables.
    let live: BTreeSet<&str> = tables.iter().map(|(t, _, _)| t.as_str()).collect();
    for entry in rls_catalog() {
        assert!(
            live.contains(entry.table),
            "catalog lists `{}` but the table does not exist",
            entry.table
        );
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn no_policy_targets_public() -> TestResult {
    let db = TestDb::new().await?;
    let offenders: Vec<(String, String)> = sqlx::query_as(
        "SELECT tablename::text, policyname::text
         FROM pg_policies
         WHERE schemaname = 'public' AND 'public' = ANY(roles)",
    )
    .fetch_all(db.migrate_pool())
    .await?;
    assert!(
        offenders.is_empty(),
        "policies must name explicit roles (TO zagrosi_app/...), found PUBLIC: {offenders:?}"
    );
    Ok(())
}
