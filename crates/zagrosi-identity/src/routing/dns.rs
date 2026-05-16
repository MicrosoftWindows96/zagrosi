// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! DNSSEC-validating DNS TXT lookup against multiple trusted resolvers.
//!
//! The system resolver (libc) does not validate DNSSEC. Using
//! `hickory-resolver` with the `dnssec-aws-lc-rs` feature flag and a
//! fixed pair of trusted upstreams (default: 1.1.1.1 + 9.9.9.9) is the
//! root-of-trust for the multi-IdP routing layer's domain-claim flow.
//! A DNS spoofing attack on the verifier path would otherwise silently
//! grant attacker-controlled domains to attacker-controlled IdPs.
//!
//! Both resolvers MUST return at least one TXT record exactly equal to
//! the expected token; mismatch surfaces as
//! [`VerifyFailure::ResolverDisagreement`]. Every per-resolver query
//! is wrapped in a [`tokio::time::timeout`] bounded by the verify
//! timeout from [`crate::config::DnsConfig::verify_timeout_ms`].

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{Resolver, TokioResolver};

use crate::error::{IdentityError, Result};

/// FQDN prefix used by the domain-ownership challenge.
///
/// The verify endpoint resolves
/// `_zagrosi-verify.<domain> IN TXT "<token>"`. Lifting the prefix
/// to a constant defends against typos drifting between the docs,
/// the production resolver path, and integration-test fixtures.
pub const VERIFY_TXT_PREFIX: &str = "_zagrosi-verify.";

/// Stable failure-mode discriminator. Carried by both
/// [`VerifyOutcome::Failed`] and the audit event payload so ops
/// dashboards can group the failure family without re-parsing
/// human-readable text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyFailure {
    /// DNSSEC chain validation rejected the answer (bogus / no
    /// signature).
    DnssecBogus,
    /// Authoritative server returned NXDOMAIN.
    NxDomain,
    /// Authoritative server returned SERVFAIL or any other
    /// transport-level failure that is not NXDOMAIN.
    ServFail,
    /// Resolution succeeded but no TXT record matched the
    /// expected token.
    NoMatchingTxt,
    /// Resolvers returned different views of the TXT record set
    /// (e.g. one matched, one did not). Treat as a failure rather
    /// than picking a winner.
    ResolverDisagreement,
    /// At least one resolver did not respond within the configured
    /// per-resolver timeout.
    Timeout,
}

impl VerifyFailure {
    /// Stable snake-case slug suitable for the audit event payload
    /// and the public `IdentityError::DomainVerificationFailed`
    /// reason field. Stays out of the `Display` impl so accidental
    /// formatting in handlers cannot leak `Debug` text.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::DnssecBogus => "dnssec_bogus",
            Self::NxDomain => "nx_domain",
            Self::ServFail => "serv_fail",
            Self::NoMatchingTxt => "no_matching_txt",
            Self::ResolverDisagreement => "resolver_disagreement",
            Self::Timeout => "timeout",
        }
    }
}

/// Outcome of a [`DnsResolverPort::verify_txt`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Every configured resolver agreed the expected TXT token is
    /// present. `resolver_path` is the stable comma-joined IP
    /// list (e.g. `"1.1.1.1+9.9.9.9"`) recorded into
    /// `org_idp_domains.last_verified_via`.
    Verified {
        /// Resolver-path attestation persisted alongside the row.
        resolver_path: String,
    },
    /// At least one resolver rejected, returned a mismatching
    /// answer, or otherwise failed. The handler maps `reason` to
    /// [`IdentityError::DomainVerificationFailed`].
    Failed {
        /// Failure-mode discriminator.
        reason: VerifyFailure,
        /// Same `resolver_path` shape as the verified case so the
        /// audit event can record which resolvers participated.
        resolver_path: String,
    },
}

/// Async port for DNSSEC TXT verification. Trait-objected so
/// production code uses [`HickoryDualResolver`] while tests inject
/// a deterministic mock.
#[async_trait]
pub trait DnsResolverPort: Send + Sync + 'static {
    /// Resolve `_zagrosi-verify.<domain>` TXT records against ALL
    /// configured resolvers. Returns
    /// [`VerifyOutcome::Verified`] only when every resolver
    /// returns a DNSSEC-validated answer that contains
    /// `expected_token` verbatim.
    ///
    /// # Errors
    ///
    /// The function returns `Ok(VerifyOutcome::Failed { .. })` for
    /// expected DNS failures (NX, SERVFAIL, mismatch). It returns
    /// `Err(IdentityError)` only for catastrophic internal errors
    /// the caller cannot reasonably interpret.
    async fn verify_txt(&self, domain: &str, expected_token: &str) -> Result<VerifyOutcome>;

    /// Stable resolver-path attestation used by the cache key
    /// + audit payload. Returns the comma-joined IP list (e.g.
    /// `"1.1.1.1+9.9.9.9"`).
    fn resolver_path(&self) -> &str;
}

/// Production implementation backed by `hickory-resolver` with
/// DNSSEC validation enabled.
pub struct HickoryDualResolver {
    resolvers: Vec<(IpAddr, TokioResolver)>,
    timeout: Duration,
    resolver_path: String,
}

impl HickoryDualResolver {
    /// Build from the parsed `ZAGROSI_DNS_RESOLVERS` IPs and the
    /// per-resolver timeout from
    /// [`crate::config::DnsConfig::verify_timeout_ms`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::MalformedDnsConfig`] when fewer
    /// than two resolvers are supplied (defence-in-depth — the
    /// startup `validate()` already rejects this).
    pub fn new(resolver_ips: &[IpAddr], timeout: Duration) -> Result<Self> {
        if resolver_ips.len() < 2 {
            return Err(IdentityError::MalformedDnsConfig {
                reason: format!(
                    "HickoryDualResolver requires >= 2 resolvers (got {})",
                    resolver_ips.len()
                ),
            });
        }

        let mut resolvers = Vec::with_capacity(resolver_ips.len());
        for ip in resolver_ips {
            // Single-resolver upstream wired over both UDP and TCP
            // so DNSSEC-signed responses (which can exceed the
            // 512-byte UDP limit before EDNS0) still resolve cleanly.
            let group = NameServerConfigGroup::from_ips_clear(&[*ip], 53, true);
            let cfg = ResolverConfig::from_parts(None, vec![], group);

            let mut opts = ResolverOpts::default();
            // EDNS0 is required for DNSSEC payloads to exceed
            // 512 bytes. `validate` enables DNSSEC chain checking
            // (gated behind the `dnssec-aws-lc-rs` cargo feature).
            opts.edns0 = true;
            opts.validate = true;

            let resolver = Resolver::builder_with_config(cfg, TokioConnectionProvider::default())
                .with_options(opts)
                .build();
            resolvers.push((*ip, resolver));
        }

        let resolver_path = resolver_path_for(resolver_ips);

        Ok(Self {
            resolvers,
            timeout,
            resolver_path,
        })
    }

    /// Wrap into the `Arc<dyn DnsResolverPort>` shape consumed by
    /// the routing handlers.
    #[must_use]
    pub fn into_port(self) -> Arc<dyn DnsResolverPort> {
        Arc::new(self)
    }
}

#[async_trait]
impl DnsResolverPort for HickoryDualResolver {
    async fn verify_txt(&self, domain: &str, expected_token: &str) -> Result<VerifyOutcome> {
        // The challenge name is `_zagrosi-verify.<domain>`. We
        // build it once and pass to every resolver so a typo in
        // the prefix does not divide the lookups.
        let qname = format!("{VERIFY_TXT_PREFIX}{domain}");

        // Run every resolver concurrently. Any timeout / NX /
        // SERVFAIL is captured in the per-resolver result; we
        // reduce them after.
        let lookups = self
            .resolvers
            .iter()
            .map(|(_ip, resolver)| {
                let qname = qname.clone();
                async move { tokio::time::timeout(self.timeout, resolver.txt_lookup(qname)).await }
            })
            .collect::<Vec<_>>();

        let results = futures::future::join_all(lookups).await;

        // Per-resolver outcome taxonomy:
        //   `Ok(true)`   the resolver returned a TXT record matching `expected_token`.
        //   `Ok(false)`  the resolver answered but no record matched.
        //   `Err(kind)`  the resolver errored out (NX / SERVFAIL / DNSSEC / timeout).
        //
        // After all results land we reduce to a single VerifyOutcome
        // so the caller distinguishes "every resolver agreed" from
        // "resolvers disagreed" (the latter is the load-bearing
        // security signal of the dual-resolver design).
        let per_resolver: Vec<core::result::Result<bool, VerifyFailure>> = results
            .into_iter()
            .map(|result| match result {
                Err(_elapsed) => Err(VerifyFailure::Timeout),
                Ok(Err(err)) => Err(classify_resolve_error(&err)),
                Ok(Ok(lookup)) => {
                    let mut matched = false;
                    for record in lookup.iter() {
                        let joined: String = record
                            .iter()
                            .filter_map(|s| std::str::from_utf8(s).ok())
                            .collect();
                        if joined == expected_token {
                            matched = true;
                            break;
                        }
                    }
                    Ok(matched)
                }
            })
            .collect();

        Ok(reduce_per_resolver_outcomes(
            &per_resolver,
            self.resolver_path.clone(),
        ))
    }

    fn resolver_path(&self) -> &str {
        &self.resolver_path
    }
}

/// Render the resolver-path attestation. Public so test helpers can
/// produce identical strings without reaching into the struct.
#[must_use]
pub fn resolver_path_for(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join("+")
}

/// Reduce per-resolver outcomes to a single [`VerifyOutcome`]. Pulled
/// into a free fn so unit tests can drive the disagreement /
/// severity / unanimous paths without a network resolver.
///
/// `per_resolver` carries the per-upstream outcome:
/// - `Ok(true)`  matched the expected token,
/// - `Ok(false)` answered cleanly with no matching record,
/// - `Err(kind)` errored (NX / SERVFAIL / DNSSEC / Timeout).
///
/// `resolver_path` is the comma-joined IP attestation surfaced
/// downstream (audit payload + `org_idp_domains.last_verified_via`).
#[must_use]
pub(crate) fn reduce_per_resolver_outcomes(
    per_resolver: &[core::result::Result<bool, VerifyFailure>],
    resolver_path: String,
) -> VerifyOutcome {
    let any_matched = per_resolver.iter().any(|r| matches!(r, Ok(true)));
    let any_dissent = per_resolver.iter().any(|r| matches!(r, Ok(false) | Err(_)));

    match (any_matched, any_dissent) {
        // Unanimous success.
        (true, false) => VerifyOutcome::Verified { resolver_path },
        // Mixed: at least one resolver matched and at least one did not.
        // This is the canonical disagreement signal.
        (true, true) => VerifyOutcome::Failed {
            reason: VerifyFailure::ResolverDisagreement,
            resolver_path,
        },
        // No resolver matched. Distinguish "every resolver answered
        // cleanly with no record" from "every resolver erred". When
        // any error fired, surface the most severe failure class so
        // ops dashboards see DNSSEC > Timeout > ServFail > NxDomain.
        (false, _) => {
            let worst = per_resolver
                .iter()
                .filter_map(|r| r.as_ref().err().copied())
                .max_by_key(|f| failure_severity(*f))
                .unwrap_or(VerifyFailure::NoMatchingTxt);
            VerifyOutcome::Failed {
                reason: worst,
                resolver_path,
            }
        }
    }
}

/// Severity rank used to pick the most informative failure reason
/// when multiple resolvers errored. Higher = more security-relevant.
const fn failure_severity(reason: VerifyFailure) -> u8 {
    match reason {
        VerifyFailure::DnssecBogus => 4,
        VerifyFailure::ResolverDisagreement => 3,
        VerifyFailure::Timeout => 2,
        VerifyFailure::ServFail => 1,
        VerifyFailure::NxDomain | VerifyFailure::NoMatchingTxt => 0,
    }
}

/// Map a `hickory_resolver::ResolveError` onto the stable failure
/// taxonomy. The crate's error kinds shift between minor versions,
/// so we prefer string matching over exhaustive enum coverage.
fn classify_resolve_error(err: &hickory_resolver::ResolveError) -> VerifyFailure {
    let rendered = format!("{err}").to_ascii_lowercase();
    if rendered.contains("dnssec") || rendered.contains("bogus") || rendered.contains("rrsig") {
        VerifyFailure::DnssecBogus
    } else if rendered.contains("nxdomain") || rendered.contains("no records found") {
        VerifyFailure::NxDomain
    } else {
        VerifyFailure::ServFail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(DnsResolverPort);
    assert_impl_all!(VerifyFailure: Send, Sync, Copy);
    assert_impl_all!(VerifyOutcome: Send, Sync, Clone);

    #[test]
    fn verify_failure_slug_is_snake_case_stable() {
        // Lock the public slug values — these surface in the
        // public IdentityError::DomainVerificationFailed reason
        // and downstream consumers (audit dashboards, SPA error
        // chips) will key off them.
        assert_eq!(VerifyFailure::DnssecBogus.slug(), "dnssec_bogus");
        assert_eq!(VerifyFailure::NxDomain.slug(), "nx_domain");
        assert_eq!(VerifyFailure::ServFail.slug(), "serv_fail");
        assert_eq!(VerifyFailure::NoMatchingTxt.slug(), "no_matching_txt");
        assert_eq!(
            VerifyFailure::ResolverDisagreement.slug(),
            "resolver_disagreement"
        );
        assert_eq!(VerifyFailure::Timeout.slug(), "timeout");
    }

    #[test]
    fn resolver_path_renders_plus_separated_ips() {
        let ips: Vec<IpAddr> = vec![
            "1.1.1.1"
                .parse()
                .unwrap_or_else(|e| panic!("ip parse: {e}")),
            "9.9.9.9"
                .parse()
                .unwrap_or_else(|e| panic!("ip parse: {e}")),
        ];
        assert_eq!(resolver_path_for(&ips), "1.1.1.1+9.9.9.9");
    }

    #[test]
    fn verify_txt_prefix_is_stable() {
        // Lock the FQDN prefix — operators publish DNS records
        // against this name; changing it breaks every existing
        // verification setup.
        assert_eq!(VERIFY_TXT_PREFIX, "_zagrosi-verify.");
    }

    #[test]
    fn reduce_unanimous_match_yields_verified() {
        let outcome =
            reduce_per_resolver_outcomes(&[Ok(true), Ok(true)], "1.1.1.1+9.9.9.9".to_string());
        assert!(matches!(outcome, VerifyOutcome::Verified { .. }));
    }

    #[test]
    fn reduce_resolver_disagreement_emerges_when_one_matches_one_misses() {
        // Spec §9.1: resolver A matches, resolver B does not → ResolverDisagreement.
        // Pre-fix this fell through to NoMatchingTxt; this test locks the fix.
        let outcome =
            reduce_per_resolver_outcomes(&[Ok(true), Ok(false)], "1.1.1.1+9.9.9.9".to_string());
        match outcome {
            VerifyOutcome::Failed { reason, .. } => {
                assert_eq!(reason, VerifyFailure::ResolverDisagreement);
            }
            other @ VerifyOutcome::Verified { .. } => {
                panic!("expected ResolverDisagreement, got {other:?}")
            }
        }
    }

    #[test]
    fn reduce_resolver_disagreement_emerges_when_one_matches_one_errors() {
        let outcome = reduce_per_resolver_outcomes(
            &[Ok(true), Err(VerifyFailure::NxDomain)],
            "1.1.1.1+9.9.9.9".to_string(),
        );
        match outcome {
            VerifyOutcome::Failed { reason, .. } => {
                assert_eq!(reason, VerifyFailure::ResolverDisagreement);
            }
            other @ VerifyOutcome::Verified { .. } => {
                panic!("expected ResolverDisagreement, got {other:?}")
            }
        }
    }

    #[test]
    fn reduce_no_match_no_error_yields_no_matching_txt() {
        let outcome =
            reduce_per_resolver_outcomes(&[Ok(false), Ok(false)], "1.1.1.1+9.9.9.9".to_string());
        match outcome {
            VerifyOutcome::Failed { reason, .. } => {
                assert_eq!(reason, VerifyFailure::NoMatchingTxt);
            }
            other @ VerifyOutcome::Verified { .. } => {
                panic!("expected NoMatchingTxt, got {other:?}")
            }
        }
    }

    #[test]
    fn reduce_picks_most_severe_failure_when_all_err() {
        // DNSSEC outweighs ServFail outweighs NxDomain.
        let outcome = reduce_per_resolver_outcomes(
            &[
                Err(VerifyFailure::NxDomain),
                Err(VerifyFailure::DnssecBogus),
            ],
            "1.1.1.1+9.9.9.9".to_string(),
        );
        match outcome {
            VerifyOutcome::Failed { reason, .. } => {
                assert_eq!(reason, VerifyFailure::DnssecBogus);
            }
            other @ VerifyOutcome::Verified { .. } => {
                panic!("expected DnssecBogus, got {other:?}")
            }
        }
    }

    #[test]
    fn reduce_timeout_outranks_servfail() {
        let outcome = reduce_per_resolver_outcomes(
            &[Err(VerifyFailure::ServFail), Err(VerifyFailure::Timeout)],
            "1.1.1.1+9.9.9.9".to_string(),
        );
        match outcome {
            VerifyOutcome::Failed { reason, .. } => {
                assert_eq!(reason, VerifyFailure::Timeout);
            }
            other @ VerifyOutcome::Verified { .. } => {
                panic!("expected Timeout, got {other:?}")
            }
        }
    }

    #[test]
    fn hickory_constructor_rejects_single_resolver() {
        let one: Vec<IpAddr> = vec![
            "1.1.1.1"
                .parse()
                .unwrap_or_else(|e| panic!("ip parse: {e}")),
        ];
        match HickoryDualResolver::new(&one, Duration::from_secs(5)) {
            Err(IdentityError::MalformedDnsConfig { .. }) => {}
            Err(other) => panic!("expected MalformedDnsConfig, got {other:?}"),
            Ok(_) => panic!("single resolver must reject construction"),
        }
    }
}
