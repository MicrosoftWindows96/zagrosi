// SPDX-License-Identifier: AGPL-3.0-or-later

//! Zagrosi API gateway placeholder.
//!
//! Initialises observability and logs a startup line, then exits zero. The
//! real gateway lands in a later split. This binary's purpose at this stage
//! is to verify that workspace dependency wiring against `zagrosi-core` is
//! correct and that the production lint set passes against a real binary.

use zagrosi_core::{CoreConfig, LoadOptions, Observability};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = CoreConfig::load(LoadOptions {
        env_prefix: "ZAGROSI_",
        file_path: None,
    })?;
    let _obs = Observability::init(&cfg)?;
    tracing::info!("zagrosi: placeholder");
    Ok(())
}
