// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plan-shape guard: the policy's GUC comparison must evaluate once per
//! statement (`InitPlan`), not per row (`SubPlan`). String-matching EXPLAIN
//! output is brittle-but-valuable — review on Postgres major upgrades.

use serial_test::serial;
use zagrosi_db::begin_tenant_tx;
use zagrosi_test_support::{TestDb, seed_org};

type TestError = Box<dyn std::error::Error + Send + Sync>;
type TestResult = Result<(), TestError>;

#[tokio::test]
#[serial]
async fn policy_predicate_evaluates_once_per_statement() -> TestResult {
    let db = TestDb::new().await?;
    let org = seed_org(db.migrate_pool(), "initplan-org").await?;

    let mut tx = begin_tenant_tx(db.app_pool(), org).await?;
    let plan_rows: Vec<String> = sqlx::query_scalar("EXPLAIN SELECT * FROM api_tokens")
        .fetch_all(tx.as_executor())
        .await?;
    tx.commit().await?;
    let plan = plan_rows.join("\n");

    assert!(
        plan.contains("InitPlan"),
        "policy GUC comparison must surface as an InitPlan (one-time \
         evaluation); plan was:\n{plan}"
    );
    assert!(
        !plan.contains("SubPlan"),
        "per-row SubPlan evaluation of the GUC predicate regressed; plan was:\n{plan}"
    );
    Ok(())
}
