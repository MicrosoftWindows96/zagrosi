// SPDX-License-Identifier: AGPL-3.0-or-later

//! NATS-backed cross-replica eviction bus.
//!
//! [`SessionEventBus`] wraps an `async-nats` client behind a thin
//! `Send + Sync + 'static` surface. When the configured broker URL
//! is empty the bus operates in no-op mode: publishes silently
//! return `Ok(())` and subscribers never produce events. The
//! resolver's fail-closed cache TTL guarantees the 1-second
//! revocation SLA still holds in this degraded mode.
//!
//! Subscribers run as a tokio task and call back into the
//! [`crate::session::cache::SessionCache`] to evict entries. The
//! bus exposes a health probe ([`SessionEventBus::is_connected`])
//! the resolver consults to decide which cache TTL to use.
//!
//! ## Subjects
//!
//! - `identity.session.revoked.<session_id>` — per-session
//!   revocation events.
//! - `identity.session.revoked-user.<user_id>` — per-user fan-out
//!   for bulk revocations driven by the SCIM deactivation path or
//!   the admin sign-out-all flow.
//! - `identity.session.updated.<session_id>` — active-org switch
//!   events. Peer replicas evict the cached entry so the next
//!   resolve picks up the new `org_id`.
//!
//! ## Reconnect semantics
//!
//! `async-nats` reconnects the underlying client transport
//! automatically, but server-side subscriptions can drop on broker
//! bounces. [`SessionEventBus::spawn_subscriber`] therefore wraps
//! the listen loop in a retry/backoff harness that re-arms the
//! three subscriptions whenever the inner loop returns.

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::session::cache::SessionCache;
use crate::session::revoke::{
    REVOKE_SUBJECT_PREFIX, REVOKE_USER_SUBJECT_PREFIX, SessionRevokedEvent,
    UserSessionsRevokedEvent,
};
use crate::session::switch_org::{SESSION_UPDATED_SUBJECT_PREFIX, SessionUpdatedEvent};

/// Failure modes of the bus' publish + subscribe surfaces.
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    /// Underlying NATS client returned an error.
    #[error("nats: {0}")]
    Nats(String),
    /// Payload could not be encoded.
    #[error("encode: {0}")]
    Encode(String),
}

/// NATS-backed cross-replica eviction bus.
#[derive(Clone)]
pub struct SessionEventBus {
    inner: Arc<BusInner>,
}

enum BusInner {
    Connected(async_nats::Client),
    Disabled,
}

impl SessionEventBus {
    /// Connect to the broker at `url`. An empty URL produces a
    /// no-op bus that the resolver still treats as healthy (the
    /// fail-closed TTL is the cache safety net for both states).
    ///
    /// # Errors
    ///
    /// Returns [`BusError::Nats`] on connection failure when `url`
    /// is non-empty. Empty URL never fails.
    pub async fn connect(url: &str) -> Result<Self, BusError> {
        if url.is_empty() {
            info!("session event bus disabled (no broker URL configured)");
            return Ok(Self {
                inner: Arc::new(BusInner::Disabled),
            });
        }
        let client = async_nats::connect(url)
            .await
            .map_err(|e| BusError::Nats(e.to_string()))?;
        info!(%url, "session event bus connected");
        Ok(Self {
            inner: Arc::new(BusInner::Connected(client)),
        })
    }

    /// Construct a bus that is always disabled. Used by tests + by
    /// `IdentityServiceDeps` callers that opt out of NATS in
    /// pre-prod environments.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(BusInner::Disabled),
        }
    }

    /// `true` when the bus has a live NATS connection. The resolver
    /// queries this on its health-tick to decide which cache TTL to
    /// use.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        match self.inner.as_ref() {
            BusInner::Connected(client) => {
                matches!(
                    client.connection_state(),
                    async_nats::connection::State::Connected
                )
            }
            BusInner::Disabled => false,
        }
    }

    /// Publish a JSON-encoded payload on the named subject. Disabled
    /// buses silently succeed.
    ///
    /// # Errors
    ///
    /// Returns [`BusError::Encode`] when JSON encoding fails;
    /// [`BusError::Nats`] when the broker rejects the publish.
    pub async fn publish<T: Serialize + Sync>(
        &self,
        subject: &str,
        payload: &T,
    ) -> Result<(), BusError> {
        match self.inner.as_ref() {
            BusInner::Disabled => Ok(()),
            BusInner::Connected(client) => {
                let bytes =
                    serde_json::to_vec(payload).map_err(|e| BusError::Encode(e.to_string()))?;
                client
                    .publish(subject.to_owned(), bytes.into())
                    .await
                    .map_err(|e| BusError::Nats(e.to_string()))
            }
        }
    }

    /// Spawn the cross-replica eviction subscriber. Listens on the
    /// per-session revoke, per-user revoke, and per-session updated
    /// subjects and drives the matching evictions on `cache`.
    /// Disabled buses spawn a no-op future that never produces work.
    ///
    /// The returned [`tokio::task::JoinHandle`] is held by the
    /// service composition so a clean shutdown can abort the loop.
    /// The harness retries on inner failures with bounded backoff
    /// so a broker bounce that drops the subscriptions does not
    /// stop the eviction stream permanently.
    #[must_use]
    pub fn spawn_subscriber(&self, cache: SessionCache) -> tokio::task::JoinHandle<()> {
        match self.inner.as_ref() {
            BusInner::Disabled => tokio::spawn(async move {
                // Nothing to do; keep the task alive so the join
                // handle's lifetime tracks the outer service.
                std::future::pending::<()>().await;
            }),
            BusInner::Connected(client) => {
                let client = client.clone();
                tokio::spawn(async move {
                    let mut backoff = Duration::from_millis(250);
                    loop {
                        match run_subscriber(&client, &cache).await {
                            Ok(()) => {
                                warn!(
                                    "session event subscriber streams ended; restarting after backoff"
                                );
                            }
                            Err(err) => {
                                error!(
                                    ?err,
                                    "session event subscriber error; restarting after backoff"
                                );
                            }
                        }
                        tokio::time::sleep(backoff).await;
                        // Cap the backoff at 30 s so a long broker
                        // outage does not stretch out the
                        // first-eviction-after-recovery latency.
                        backoff = std::cmp::min(backoff * 2, Duration::from_secs(30));
                    }
                })
            }
        }
    }
}

async fn run_subscriber(client: &async_nats::Client, cache: &SessionCache) -> Result<(), BusError> {
    use futures::StreamExt;

    let per_session_subject = format!("{REVOKE_SUBJECT_PREFIX}.*");
    let per_user_subject = format!("{REVOKE_USER_SUBJECT_PREFIX}.*");
    let updated_subject = format!("{SESSION_UPDATED_SUBJECT_PREFIX}.*");
    let mut per_session = client
        .subscribe(per_session_subject.clone())
        .await
        .map_err(|e| BusError::Nats(e.to_string()))?;
    let mut per_user = client
        .subscribe(per_user_subject.clone())
        .await
        .map_err(|e| BusError::Nats(e.to_string()))?;
    let mut updated = client
        .subscribe(updated_subject.clone())
        .await
        .map_err(|e| BusError::Nats(e.to_string()))?;
    info!(
        %per_session_subject,
        %per_user_subject,
        %updated_subject,
        "session event subscriber armed",
    );

    loop {
        tokio::select! {
            Some(msg) = per_session.next() => {
                match serde_json::from_slice::<SessionRevokedEvent>(&msg.payload) {
                    Ok(event) => {
                        debug!(session_id = %event.session_id, "evicting cache for revoked session");
                        cache.evict_by_session_id(event.session_id).await;
                    }
                    Err(err) => warn!(?err, "decode SessionRevokedEvent"),
                }
            }
            Some(msg) = per_user.next() => {
                match serde_json::from_slice::<UserSessionsRevokedEvent>(&msg.payload) {
                    Ok(event) => {
                        debug!(user_id = %event.user_id, "purging cache for bulk-revoked user");
                        // Per-user fan-out: a fully accurate
                        // implementation would walk every cached
                        // entry and evict by user_id; the simpler
                        // (and safe) fallback is to invalidate the
                        // cache wholesale because bulk events are
                        // rare and the cache rebuilds within the
                        // active TTL.
                        cache.invalidate_all();
                    }
                    Err(err) => warn!(?err, "decode UserSessionsRevokedEvent"),
                }
            }
            Some(msg) = updated.next() => {
                match serde_json::from_slice::<SessionUpdatedEvent>(&msg.payload) {
                    Ok(event) => {
                        debug!(session_id = %event.session_id, "evicting cache for updated session");
                        cache.evict_by_session_id(event.session_id).await;
                    }
                    Err(err) => warn!(?err, "decode SessionUpdatedEvent"),
                }
            }
            else => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn disabled_bus_publish_succeeds() {
        let bus = SessionEventBus::disabled();
        let event = SessionRevokedEvent {
            session_id: Uuid::nil(),
            user_id: Uuid::nil(),
            revoked_at: chrono::Utc::now(),
        };
        bus.publish("any.subject", &event)
            .await
            .expect("noop publish");
    }

    #[tokio::test]
    async fn disabled_bus_reports_disconnected() {
        let bus = SessionEventBus::disabled();
        assert!(!bus.is_connected());
    }

    #[tokio::test]
    async fn empty_url_produces_disabled_bus() {
        let bus = SessionEventBus::connect("").await.expect("empty url ok");
        assert!(!bus.is_connected());
    }
}
