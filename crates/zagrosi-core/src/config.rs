// SPDX-License-Identifier: AGPL-3.0-or-later

//! Layered configuration loader.
//!
//! Reads configuration from environment variables and an optional TOML file,
//! using `figment` for layering. Environment values take precedence; the file
//! fills gaps. Unknown fields in the file are tolerated so future-version
//! configs can be deserialised without erroring on fields this crate does not
//! yet recognise.

use figment::Figment;
use figment::providers::{Env, Format, Toml};

use crate::Result;

/// Top-level configuration consumed by `zagrosi-core` and downstream crates.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", default)]
pub struct CoreConfig {
    /// Service identifier emitted on every log line and OpenTelemetry span.
    pub service_name: String,
    /// Log output format. Defaults to JSON for production deployments.
    pub log_format: LogFormat,
    /// Optional OTLP HTTP endpoint (for example `http://otel-collector:4318`).
    /// When `None`, the OpenTelemetry layer is not installed.
    pub otel_endpoint: Option<String>,
    /// Optional bind address for the Prometheus admin server (for example
    /// `127.0.0.1:9090`). When `None`, the metrics admin server is not started.
    pub prometheus_bind: Option<String>,
}

/// Format used by the `tracing-subscriber` `fmt` layer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON output. Production default.
    #[default]
    Json,
    /// Pretty multi-line output for local development.
    Pretty,
}

/// Options accepted by [`CoreConfig::load`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LoadOptions<'a> {
    /// Environment variable prefix. Conventionally `"ZAGROSI_"`.
    pub env_prefix: &'a str,
    /// Optional path to a TOML configuration file.
    pub file_path: Option<&'a std::path::Path>,
}

impl CoreConfig {
    /// Load configuration from environment variables and (optionally) a TOML
    /// file. Environment values take precedence; the file fills gaps.
    ///
    /// Unknown fields in the file are tolerated. Malformed env values or
    /// malformed TOML surface as [`ZagrosiError::Config`].
    ///
    /// # Errors
    ///
    /// Returns [`ZagrosiError::Config`] when environment values or file
    /// contents fail to deserialise into [`CoreConfig`].
    pub fn load(opts: LoadOptions<'_>) -> Result<Self> {
        let mut figment = Figment::new();
        if let Some(path) = opts.file_path {
            figment = figment.merge(Toml::file(path));
        }
        figment = figment.merge(Env::prefixed(opts.env_prefix));
        figment.extract().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // All env-touching tests use `figment::Jail`, which scopes environment
    // variables and the working directory to the closure. This avoids both
    // unsafe `std::env::set_var` (forbidden by `unsafe_code = "forbid"`) and
    // cross-test pollution from process-wide env state.

    #[test]
    fn empty_env_and_no_file_yields_default() {
        figment::Jail::expect_with(|_jail| {
            let cfg = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.service_name, "");
            assert_eq!(cfg.log_format, LogFormat::Json);
            assert!(cfg.otel_endpoint.is_none());
            assert!(cfg.prometheus_bind.is_none());
            Ok(())
        });
    }

    #[test]
    fn env_log_format_pretty_parses() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("ZAGROSI_LOG_FORMAT", "pretty");
            let cfg = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.log_format, LogFormat::Pretty);
            Ok(())
        });
    }

    #[test]
    fn file_only_loads_log_format() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("test.toml", "log_format = \"pretty\"\n")?;
            let path = jail.directory().join("test.toml");
            let cfg = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.log_format, LogFormat::Pretty);
            Ok(())
        });
    }

    #[test]
    fn env_overrides_file_value() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("test.toml", "service_name = \"from-file\"\n")?;
            jail.set_env("ZAGROSI_SERVICE_NAME", "from-env");
            let path = jail.directory().join("test.toml");
            let cfg = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.service_name, "from-env");
            Ok(())
        });
    }

    #[test]
    fn unknown_fields_in_file_are_tolerated() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("test.toml", "unknown_future_field = \"ignored\"\n")?;
            let path = jail.directory().join("test.toml");
            let cfg = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            })
            .map_err(|e| figment::Error::from(e.to_string()))?;
            assert_eq!(cfg.log_format, LogFormat::Json);
            Ok(())
        });
    }

    #[test]
    fn malformed_env_value_returns_config_error() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("ZAGROSI_LOG_FORMAT", "neither-json-nor-pretty");
            let result = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: None,
            });
            assert!(result.is_err(), "expected error for malformed env value");
            Ok(())
        });
    }

    #[test]
    fn malformed_toml_returns_config_error() {
        figment::Jail::expect_with(|jail| {
            jail.create_file("broken.toml", "this is = not valid [[ toml\n")?;
            let path = jail.directory().join("broken.toml");
            let result = CoreConfig::load(LoadOptions {
                env_prefix: "ZAGROSI_",
                file_path: Some(&path),
            });
            assert!(result.is_err(), "expected error for malformed TOML");
            Ok(())
        });
    }
}
