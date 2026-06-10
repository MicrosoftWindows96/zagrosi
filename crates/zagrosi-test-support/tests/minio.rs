// SPDX-License-Identifier: AGPL-3.0-or-later

//! `MinIO` + `pg_parquet` round-trip: validates the server-side S3 env and
//! shared-network wiring before audit archival (section 15) depends on it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use zagrosi_test_support::TestDb;

type TestError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::test]
#[serial_test::serial]
async fn minio_parquet_round_trip() -> Result<(), TestError> {
    let (db, minio) = TestDb::with_minio().await?;

    // pg_parquet object-store access is superuser-or-granted-role; the
    // bootstrap pool exercises the plain superuser path here (the
    // maintenance-role grant is asserted by section 15's archival tests).
    let object_uri = format!("{}/smoke.parquet", minio.bucket_uri());
    let sql = format!(
        r"
CREATE TABLE parquet_smoke (id BIGINT, label TEXT);
INSERT INTO parquet_smoke VALUES (1, 'a'), (2, 'b'), (3, 'c');
COPY (SELECT * FROM parquet_smoke ORDER BY id) TO '{object_uri}' (format 'parquet');
CREATE TABLE parquet_smoke_back (id BIGINT, label TEXT);
COPY parquet_smoke_back FROM '{object_uri}' (format 'parquet');
"
    );
    sqlx::raw_sql(&sql).execute(db.bootstrap_pool()).await?;

    let (count, back_count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM parquet_smoke),
                (SELECT count(*) FROM parquet_smoke_back)",
    )
    .fetch_one(db.bootstrap_pool())
    .await?;
    assert_eq!(count, 3);
    assert_eq!(back_count, 3, "round-tripped row count mismatch");
    Ok(())
}
