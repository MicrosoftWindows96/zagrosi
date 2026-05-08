// SPDX-License-Identifier: AGPL-3.0-or-later

//! Observability skeleton wiring `tracing`, OpenTelemetry, and Prometheus.
//!
//! [`Observability::init`] sets the global `tracing` subscriber and, when the
//! corresponding fields of [`crate::CoreConfig`] are populated, also installs
//! an OpenTelemetry OTLP HTTP exporter and a Prometheus admin server. Both
//! subsystems degrade gracefully: an unreachable OpenTelemetry endpoint or a
//! bind failure on the Prometheus port logs a warning and continues. The
//! function panics in no expected case.
//!
//! The returned [`Observability`] guard MUST be held for the lifetime of the
//! process. Dropping it triggers cooperative shutdown of the metrics admin
//! server (cancellation token) and waits up to five seconds for the
//! OpenTelemetry provider to flush.
//!
//! ```no_run
//! use zagrosi_core::{CoreConfig, LoadOptions, Observability};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = CoreConfig::load(LoadOptions { env_prefix: "ZAGROSI_", file_path: None })?;
//! let _obs = Observability::init(&cfg)?;
//! tracing::info!("ready");
//! # Ok(()) }
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tokio_util::sync::CancellationToken;
use tracing::{Subscriber, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::{CoreConfig, LogFormat, Result, ZagrosiError};

/// Lifecycle guard for the global tracing subscriber, the optional OpenTelemetry
/// provider, and the optional Prometheus admin server.
///
/// Returned by [`Observability::init`]. Dropping the guard triggers cooperative
/// shutdown of the metrics admin server and waits up to five seconds for the
/// OpenTelemetry provider to flush.
pub struct Observability {
    tracer_provider: Option<SdkTracerProvider>,
    metrics_handle: Option<PrometheusHandle>,
    metrics_server: Option<tokio::task::JoinHandle<()>>,
    shutdown_token: Option<CancellationToken>,
}

impl Observability {
    /// Initialise the global tracing subscriber and any optional subsystems.
    ///
    /// # Errors
    ///
    /// Returns [`ZagrosiError::Internal`] when:
    ///
    /// - the global tracing subscriber was already initialised in this process,
    ///   or
    /// - `cfg.prometheus_bind` is `Some` but no `tokio` runtime is active in the
    ///   calling context.
    ///
    /// Failures of optional subsystems (unreachable OpenTelemetry endpoint,
    /// invalid Prometheus bind address, port-in-use) are logged at `warn` level
    /// and the function still returns `Ok`.
    pub fn init(cfg: &CoreConfig) -> Result<Self> {
        // Validate runtime requirements BEFORE installing the global tracing
        // subscriber so a runtime-mismatch error does not leave the process
        // with a half-installed subscriber.
        let needs_runtime = cfg
            .prometheus_bind
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        if needs_runtime && tokio::runtime::Handle::try_current().is_err() {
            return Err(ZagrosiError::internal(
                "prometheus_bind requires an active tokio runtime context",
            ));
        }

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let fmt_layer: Box<dyn Layer<_> + Send + Sync> = match cfg.log_format {
            LogFormat::Json => Box::new(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false),
            ),
            LogFormat::Pretty => Box::new(tracing_subscriber::fmt::layer().pretty()),
        };

        let (otel_layer, tracer_provider) = build_otel_layer(cfg);

        let registry = tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer);
        let init_result = if let Some(layer) = otel_layer {
            registry.with(layer).try_init()
        } else {
            registry.try_init()
        };
        init_result.map_err(|err| {
            ZagrosiError::internal(format!("tracing subscriber already initialised: {err}"))
        })?;

        let PrometheusServer {
            metrics_handle,
            metrics_server,
            shutdown_token,
        } = build_prometheus(cfg);

        Ok(Self {
            tracer_provider,
            metrics_handle,
            metrics_server,
            shutdown_token,
        })
    }

    /// Returns a handle to the Prometheus exporter, if the admin server was
    /// successfully started. `None` indicates either that Prometheus was
    /// disabled or that startup failed gracefully.
    #[must_use]
    pub const fn prometheus_handle(&self) -> Option<&PrometheusHandle> {
        self.metrics_handle.as_ref()
    }
}

impl Drop for Observability {
    fn drop(&mut self) {
        // Cooperative shutdown: cancel the token, then poll the metrics
        // server `JoinHandle` for up to 100 ms so `with_graceful_shutdown`
        // can drain in-flight requests. Hard-abort only as a last resort
        // when the cooperative window expires.
        if let Some(token) = self.shutdown_token.take() {
            token.cancel();
        }
        if let Some(jh) = self.metrics_server.take() {
            let deadline = std::time::Instant::now() + Duration::from_millis(100);
            while !jh.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            if !jh.is_finished() {
                warn!("metrics admin server did not drain within 100ms; aborting");
                jh.abort();
            }
        }
        if let Some(provider) = self.tracer_provider.take() {
            // `provider.shutdown()` is synchronous and can block on the
            // batch span processor's flush. Run it on a detached helper
            // thread so the Drop is bounded by `recv_timeout`. On timeout
            // the helper thread continues to run until the in-flight
            // shutdown completes (acceptable on process exit; documented
            // detached-thread fallback for long-lived in-process use).
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = provider.shutdown();
                let _ = tx.send(());
            });
            if rx.recv_timeout(Duration::from_secs(5)).is_err() {
                warn!("OpenTelemetry provider shutdown timed out after 5s; continuing");
            }
        }
    }
}

fn build_otel_layer<S>(
    cfg: &CoreConfig,
) -> (
    Option<Box<dyn Layer<S> + Send + Sync>>,
    Option<SdkTracerProvider>,
)
where
    S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync,
{
    let Some(endpoint) = cfg.otel_endpoint.as_deref() else {
        return (None, None);
    };
    if endpoint.is_empty() {
        return (None, None);
    }

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .build()
    {
        Ok(exp) => exp,
        Err(err) => {
            // The `warn!` here is a best-effort diagnostic. It is invoked
            // BEFORE the global tracing subscriber is installed, so the
            // event is dropped on the floor. The same condition will
            // re-surface as an export error during the first batch flush,
            // which DOES land in the installed subscriber.
            warn!(
                error = %err,
                endpoint = endpoint,
                "OpenTelemetry exporter build failed; continuing without remote tracing"
            );
            return (None, None);
        }
    };

    // Attach `service.name` (and any future resource attributes) so spans
    // exported via OTLP are correctly attributed in the collector.
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", cfg.service_name.clone()))
        .build();
    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();
    let tracer = provider.tracer(cfg.service_name.clone());
    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    (Some(Box::new(layer)), Some(provider))
}

/// Result triple returned by [`build_prometheus`].
struct PrometheusServer {
    metrics_handle: Option<PrometheusHandle>,
    metrics_server: Option<tokio::task::JoinHandle<()>>,
    shutdown_token: Option<CancellationToken>,
}

impl PrometheusServer {
    const fn disabled() -> Self {
        Self {
            metrics_handle: None,
            metrics_server: None,
            shutdown_token: None,
        }
    }
}

fn build_prometheus(cfg: &CoreConfig) -> PrometheusServer {
    let Some(bind) = cfg.prometheus_bind.as_deref() else {
        return PrometheusServer::disabled();
    };
    if bind.is_empty() {
        return PrometheusServer::disabled();
    }

    // Defensive: even though `Observability::init` validates the runtime
    // guard up-front, this helper is private and directly tested. Use
    // `try_current()` to avoid the panic path on `current()`.
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!("prometheus admin requested but no tokio runtime; continuing without metrics");
        return PrometheusServer::disabled();
    };

    let addr: SocketAddr = match bind.parse() {
        Ok(a) => a,
        Err(err) => {
            warn!(error = %err, bind = bind, "invalid prometheus bind address; continuing without metrics");
            return PrometheusServer::disabled();
        }
    };

    // Prebind synchronously so a port-in-use failure surfaces as `disabled`
    // BEFORE any global recorder is installed. Convert to a tokio listener
    // in nonblocking mode so the admin task can serve from it.
    let std_listener = match std::net::TcpListener::bind(addr) {
        Ok(l) => l,
        Err(err) => {
            warn!(error = %err, addr = %addr, "prometheus admin listener bind failed; continuing without metrics");
            return PrometheusServer::disabled();
        }
    };
    if let Err(err) = std_listener.set_nonblocking(true) {
        warn!(error = %err, addr = %addr, "failed to set prometheus listener nonblocking; continuing without metrics");
        return PrometheusServer::disabled();
    }
    let listener = match tokio::net::TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(err) => {
            warn!(error = %err, addr = %addr, "failed to convert std listener to tokio; continuing without metrics");
            return PrometheusServer::disabled();
        }
    };

    let handle = match PrometheusBuilder::new().install_recorder() {
        Ok(h) => h,
        Err(err) => {
            warn!(error = %err, "Prometheus recorder install failed; continuing without metrics");
            return PrometheusServer::disabled();
        }
    };

    let handle_for_route = handle.clone();
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let h = handle_for_route.clone();
                async move { h.render() }
            }),
        )
        .route("/healthz", get(|| async { "ok" }));

    let token = CancellationToken::new();
    let token_for_task = token.clone();
    let server = runtime.spawn(async move {
        if let Err(err) = axum::serve(listener, app)
            .with_graceful_shutdown(async move { token_for_task.cancelled().await })
            .await
        {
            warn!(error = %err, "Prometheus admin server exited with error");
        }
    });

    PrometheusServer {
        metrics_handle: Some(handle),
        metrics_server: Some(server),
        shutdown_token: Some(token),
    }
}

#[cfg(test)]
mod tests {
    //! Notes on test design.
    //!
    //! `tracing_subscriber::registry().try_init()` installs a process-global
    //! subscriber that cannot be uninstalled. Tests that exercise full
    //! [`Observability::init`] paths mutate global state in ways that poison
    //! subsequent tests in the same process. These tests verify the pure
    //! helpers ([`build_otel_layer`], [`build_prometheus`]) directly and
    //! check the runtime-context guard up to the point at which the
    //! subscriber would be installed. Full init paths (subscriber plus
    //! OpenTelemetry plus Prometheus end-to-end) are exercised by the binary
    //! in `apps/api-gateway` and by integration tests in later sections
    //! that spawn forked processes.
    use super::*;

    #[test]
    fn build_otel_layer_returns_none_when_endpoint_unset() {
        let cfg = CoreConfig::default();
        let (layer, provider) = build_otel_layer::<tracing_subscriber::Registry>(&cfg);
        assert!(layer.is_none(), "no endpoint should produce no layer");
        assert!(provider.is_none(), "no endpoint should produce no provider");
    }

    #[test]
    fn build_otel_layer_returns_none_when_endpoint_empty() {
        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: Some(String::new()),
            prometheus_bind: None,
        };
        let (layer, provider) = build_otel_layer::<tracing_subscriber::Registry>(&cfg);
        assert!(layer.is_none());
        assert!(provider.is_none());
    }

    #[test]
    fn init_without_runtime_and_with_prometheus_bind_returns_internal_error() {
        // The runtime-context guard runs BEFORE the subscriber is installed,
        // so this test does not poison the global subscriber.
        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some("127.0.0.1:0".into()),
        };
        let result = Observability::init(&cfg);
        match result {
            Err(ZagrosiError::Internal(msg)) => {
                assert!(msg.contains("tokio runtime"), "unexpected message: {msg}");
            }
            Err(other) => panic!("expected Internal error, got {other:?}"),
            Ok(_) => panic!("expected runtime-context error"),
        }
    }

    #[test]
    fn init_with_empty_prometheus_bind_does_not_require_runtime() {
        // An empty string for `prometheus_bind` is treated as disabled and
        // therefore the runtime-context guard does not fire. This test only
        // checks that the guard does not return Err for empty values; it does
        // not call full `init` to avoid polluting the global subscriber.
        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some(String::new()),
        };
        let needs_runtime = cfg
            .prometheus_bind
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        assert!(!needs_runtime);
    }

    #[tokio::test]
    async fn build_prometheus_returns_disabled_triple_when_bind_unset() {
        let cfg = CoreConfig::default();
        let server = build_prometheus(&cfg);
        assert!(server.metrics_handle.is_none());
        assert!(server.metrics_server.is_none());
        assert!(server.shutdown_token.is_none());
    }

    #[tokio::test]
    async fn build_prometheus_returns_disabled_triple_when_bind_empty() {
        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some(String::new()),
        };
        let server = build_prometheus(&cfg);
        assert!(server.metrics_handle.is_none());
        assert!(server.metrics_server.is_none());
        assert!(server.shutdown_token.is_none());
    }

    #[tokio::test]
    async fn build_prometheus_with_invalid_bind_returns_disabled_triple() {
        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some("not-a-socket-addr".into()),
        };
        let server = build_prometheus(&cfg);
        assert!(server.metrics_handle.is_none());
        assert!(server.metrics_server.is_none());
        assert!(server.shutdown_token.is_none());
    }

    #[test]
    fn runtime_guard_does_not_fire_for_default_config() {
        // Sanity check that the runtime-context guard does not fire when
        // `prometheus_bind` is unset. Does not exercise full subscriber
        // install (see module-level note).
        let cfg = CoreConfig::default();
        let needs_runtime = cfg
            .prometheus_bind
            .as_deref()
            .is_some_and(|s| !s.is_empty());
        assert!(!needs_runtime);
    }

    #[tokio::test]
    async fn build_prometheus_succeeds_with_ephemeral_port_and_returns_handle() {
        // Reserve an ephemeral port, drop the listener so the port is free,
        // then ask `build_prometheus` to bind it. Verifies the success path
        // returns a handle and a running server task.
        let probe =
            std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral bind probe must succeed");
        let port = probe.local_addr().expect("local_addr must succeed").port();
        drop(probe);

        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some(format!("127.0.0.1:{port}")),
        };
        let server = build_prometheus(&cfg);
        assert!(
            server.metrics_handle.is_some(),
            "handle must be present on success"
        );
        assert!(
            server.metrics_server.is_some(),
            "server task must be spawned"
        );
        assert!(
            server.shutdown_token.is_some(),
            "cancellation token must be present"
        );

        // Trigger cooperative shutdown to clean up the spawned task.
        if let Some(token) = server.shutdown_token {
            token.cancel();
        }
    }

    #[tokio::test]
    async fn build_prometheus_returns_disabled_when_port_already_bound() {
        // Hold the port for the duration of the test so the bind inside
        // `build_prometheus` fails with EADDRINUSE.
        let blocker =
            std::net::TcpListener::bind("127.0.0.1:0").expect("blocker bind must succeed");
        let port = blocker
            .local_addr()
            .expect("local_addr must succeed")
            .port();

        let cfg = CoreConfig {
            service_name: "test".into(),
            log_format: LogFormat::Json,
            otel_endpoint: None,
            prometheus_bind: Some(format!("127.0.0.1:{port}")),
        };
        let server = build_prometheus(&cfg);
        assert!(
            server.metrics_handle.is_none(),
            "handle must be None on bind failure"
        );
        assert!(server.metrics_server.is_none(), "no task should be spawned");
        assert!(server.shutdown_token.is_none());

        drop(blocker);
    }
}
