// SPDX-License-Identifier: AGPL-3.0-or-later

//! `MinIO` harness for `pg_parquet` S3 round-trips.
//!
//! Starts `MinIO` on a per-test docker network; the Postgres container joins
//! the same network and receives the server-side S3 env (the section-01
//! contract: `pg_parquet`'s object-store access is entirely server-side).

use crate::error::HarnessError;
use testcontainers_modules::minio::MinIO;
use testcontainers_modules::testcontainers::core::ExecCommand;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

/// `MinIO` root credentials (image defaults; test-only).
const ACCESS_KEY: &str = "minioadmin";
const SECRET_KEY: &str = "minioadmin";

/// Pinned `MinIO` tag — mirrors `deploy/docker/compose.yaml`.
const MINIO_TAG: &str = "RELEASE.2025-09-07T16-13-09Z";

/// Bucket provisioned for parquet round-trips and (later) archival e2e.
const BUCKET: &str = "zagrosi-audit";

/// A running `MinIO` container on a shared network, with one provisioned
/// bucket. Section 15 reuses this for archival end-to-end tests.
pub struct MinioHarness {
    container: ContainerAsync<MinIO>,
    alias: String,
}

impl MinioHarness {
    /// Start `MinIO` on `network` and provision the bucket.
    ///
    /// # Errors
    ///
    /// Fails if the container cannot start or bucket creation fails.
    // testcontainers' exec stream type is `Send` but not `Sync`; holding it
    // across an await point trips the nursery lint. Upstream type, dev-only
    // crate, futures are consumed locally — not a real Send hazard.
    #[allow(clippy::future_not_send)]
    pub(crate) async fn start(network: &str) -> Result<Self, HarnessError> {
        let alias = format!("zg-minio-{}", Uuid::now_v7().simple());
        let container = MinIO::default()
            .with_tag(MINIO_TAG)
            .with_network(network)
            .with_container_name(alias.clone())
            .start()
            .await?;
        let harness = Self { container, alias };
        harness.create_bucket(BUCKET).await?;
        Ok(harness)
    }

    /// Provision a bucket idempotently via the `mc` binary bundled in the
    /// `MinIO` server image (the documented healthcheck/client pattern; the
    /// single-drive data format ignores plain `mkdir`). All command parts
    /// are crate constants — no external input reaches the shell.
    #[allow(clippy::future_not_send)] // upstream exec stream is !Sync; see start()
    async fn create_bucket(&self, bucket: &str) -> Result<(), HarnessError> {
        let cmd = format!(
            "mc alias set local http://127.0.0.1:9000 {ACCESS_KEY} {SECRET_KEY} \
             && mc mb --ignore-existing local/{bucket}"
        );
        let mut result = self
            .container
            .exec(ExecCommand::new(["/bin/sh", "-c", &cmd]))
            .await?;
        // Drain the streams first: exit_code() reports None until the exec
        // finishes, and finishing is only observable once output is consumed.
        let stdout = result
            .stdout_to_vec()
            .await
            .map_err(|e| HarnessError::Config(format!("mc exec stdout read failed: {e}")))?;
        let stderr = result
            .stderr_to_vec()
            .await
            .map_err(|e| HarnessError::Config(format!("mc exec stderr read failed: {e}")))?;
        let mut exit = result.exit_code().await?;
        for _ in 0..20 {
            if exit.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            exit = result.exit_code().await?;
        }
        if exit != Some(0) {
            return Err(HarnessError::Config(format!(
                "mc bucket provisioning exited {exit:?}: stdout={} stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            )));
        }
        Ok(())
    }

    /// S3 endpoint as seen from inside the docker network (what Postgres'
    /// `AWS_ENDPOINT_URL` must be).
    #[must_use]
    pub fn internal_endpoint(&self) -> String {
        format!("http://{}:9000", self.alias)
    }

    /// Provisioned bucket name.
    #[must_use]
    pub const fn bucket(&self) -> &'static str {
        BUCKET
    }

    /// `s3://` URI prefix for the provisioned bucket.
    #[must_use]
    pub fn bucket_uri(&self) -> String {
        format!("s3://{BUCKET}")
    }

    /// Root access key (server-side env for Postgres).
    #[must_use]
    pub const fn access_key(&self) -> &'static str {
        ACCESS_KEY
    }

    /// Root secret key (server-side env for Postgres).
    #[must_use]
    pub const fn secret_key(&self) -> &'static str {
        SECRET_KEY
    }
}
