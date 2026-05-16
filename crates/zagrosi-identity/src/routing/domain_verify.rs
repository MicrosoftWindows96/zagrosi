// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Domain CRUD handlers (`/v1/orgs/{org_slug}/idps/{id}/domains/...`).
//!
//! Three endpoints:
//!
//! - `POST   .../domains` — create an unverified claim + issue a
//!   `vrf_*` TXT challenge.
//! - `POST   .../domains/{domain_id}/verify` — run the dual-resolver
//!   DNSSEC TXT lookup and flip `verified_at`.
//! - `DELETE .../domains/{domain_id}` — soft-delete the claim.
//!
//! Every handler:
//!
//! - Reads `Extension<AuthContext>` so a future RBAC layer can drop
//!   in alongside the v0.1 org-membership predicate.
//! - Resolves `org_slug → org_id` via `OrgRepo` and rejects
//!   cross-org probes with `404 not_found` (the project-wide
//!   no-existence-oracle convention).
//! - Mints / persists / audits via [`crate::repo::OrgIdpDomainRepo`]
//!   and [`zagrosi_core::Auditor`].

use std::str::FromStr;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zagrosi_core::{
    AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, AuthContext,
};

use crate::domain::token_format::{TokenPrefix, mint};
use crate::error::{IdentityError, Result};
use crate::repo::{NewOrgIdpDomain, OrgScoped};

use super::blocklist::is_public_domain;
use super::cache::DomainKey;
use super::dns::{VERIFY_TXT_PREFIX, VerifyOutcome};
use super::state::RoutingState;

/// Request body for `POST .../domains`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDomainRequest {
    /// Domain to claim. Stored as entered (case preserved); the
    /// blocklist + lookup paths normalise to lower / IDNA before
    /// matching.
    pub domain: String,
    /// Picker priority. Optional; defaults to `100`.
    #[serde(default = "default_priority")]
    pub priority: i32,
}

const fn default_priority() -> i32 {
    100
}

/// Response body for `POST .../domains`.
#[derive(Debug, Clone, Serialize)]
pub struct CreateDomainResponse {
    /// New domain row id.
    pub id: Uuid,
    /// Domain echoed back as stored.
    pub domain: String,
    /// `vrf_*`-prefixed challenge token. The admin SPA renders this
    /// alongside the DNS instructions.
    pub challenge_token: String,
    /// Pre-rendered DNS record line that the admin pastes into
    /// their authoritative-DNS console. Includes the
    /// `_zagrosi-verify.<domain>` prefix and the IN TXT
    /// invocation so a copy-paste lands without further editing.
    pub verify_dns_record: String,
    /// Echoed priority.
    pub priority: i32,
}

/// Response body for `POST .../domains/{domain_id}/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyDomainResponse {
    /// Domain row id.
    pub id: Uuid,
    /// Domain echoed back.
    pub domain: String,
    /// Resolver-path attestation persisted into
    /// `org_idp_domains.last_verified_via`.
    pub last_verified_via: String,
    /// `verified_at` ISO-8601 timestamp.
    pub verified_at: chrono::DateTime<chrono::Utc>,
}

/// Axum handler for `POST .../domains`.
pub async fn create_domain(
    State(state): State<RoutingState>,
    Extension(auth): Extension<AuthContext>,
    Path((org_slug, org_idp_id)): Path<(String, Uuid)>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Response> {
    let org_id = resolve_org_or_404(&state, &org_slug, &auth).await?;

    let normalised_domain = normalise_domain(&req.domain)?;
    if is_public_domain(&normalised_domain) {
        return Err(IdentityError::PublicEmailDomainCannotBeClaimed);
    }

    let challenge = mint(TokenPrefix::Verification);
    let id = Uuid::now_v7();
    // Persist the canonical (IDNA-punycoded, lowercased) form so the
    // routing-lookup partial index matches against the same key the
    // discover handler computes from the user-supplied email. Storing
    // the as-entered Unicode would make IDN claims (e.g. `bücher.example`)
    // unreachable from `xn--bcher-kva.example` lookups.
    let row = OrgScoped::new(&state.org_idp_domain_repo, org_id)
        .create(NewOrgIdpDomain {
            id,
            org_idp_id,
            domain: normalised_domain.as_str(),
            challenge_token: challenge.as_str(),
            priority: req.priority,
        })
        .await?;

    state
        .auditor
        .record(AuditEvent::V1(AuditEventV1::new(
            AuditEventKind::IdpDomainCreated,
            actor_from(&auth),
            AuditResource::IdpDomain { domain_id: row.id },
            auth.correlation_id(),
            org_id,
            AuditPayload::new(serde_json::json!({
                "org_idp_id": org_idp_id,
                "domain_lower": normalised_domain,
            })),
        )))
        .await;

    let body = CreateDomainResponse {
        id: row.id,
        domain: row.domain.clone(),
        challenge_token: challenge.clone(),
        verify_dns_record: format!("{VERIFY_TXT_PREFIX}{} IN TXT \"{}\"", row.domain, challenge,),
        priority: row.priority,
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

/// Axum handler for `POST .../domains/{domain_id}/verify`.
pub async fn verify_domain(
    State(state): State<RoutingState>,
    Extension(auth): Extension<AuthContext>,
    Path((org_slug, org_idp_id, domain_id)): Path<(String, Uuid, Uuid)>,
) -> Result<Response> {
    let org_id = resolve_org_or_404(&state, &org_slug, &auth).await?;

    // Load the row first so the verify path has the persisted
    // challenge token to match against. Cross-org / unknown rows
    // surface as 404.
    let row = OrgScoped::new(&state.org_idp_domain_repo, org_id)
        .find_in_idp(org_idp_id, domain_id)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;

    let normalised_domain = normalise_domain(&row.domain)?;
    if is_public_domain(&normalised_domain) {
        // Defence-in-depth: create rejected this earlier, but a
        // future PSL update could classify a previously-clean
        // domain as public. Reject before going to the resolver.
        return Err(IdentityError::PublicEmailDomainCannotBeClaimed);
    }

    if row.challenge_token.is_empty() {
        // Legacy row without a challenge token (pre-migration-020
        // placeholder). The admin SPA must POST /domains again to
        // mint one before verify can run. Audit the failure so the
        // event family stays consistent — every failure outcome of
        // this handler emits `IdpDomainFailed`.
        emit_failed_audit(
            state.auditor.as_ref(),
            &auth,
            row.id,
            org_id,
            org_idp_id,
            &normalised_domain,
            "",
            MISSING_CHALLENGE_TOKEN_SLUG,
        )
        .await;
        return Err(IdentityError::DomainVerificationFailed {
            reason: MISSING_CHALLENGE_TOKEN_SLUG,
        });
    }

    // Cache short-circuit. Verified outcomes inside the TTL window
    // skip the resolver round-trip AND the DB UPDATE / audit
    // re-emission. Spec §"10-min cache (Moka)": damp admin spam.
    // Failed outcomes are not cached (see `cache.rs`).
    let cache_key = DomainKey {
        domain: normalised_domain.clone(),
        challenge_token: row.challenge_token.clone(),
    };
    if let Some(VerifyOutcome::Verified { resolver_path }) =
        state.domain_cache.get(&cache_key).await
    {
        // Cached success: return the row's existing `verified_at` +
        // `last_verified_via` without re-mutating the DB or emitting
        // a duplicate audit event. The first verify within the TTL
        // window is the authoritative one.
        let body = VerifyDomainResponse {
            id: row.id,
            domain: row.domain,
            last_verified_via: row
                .last_verified_via
                .unwrap_or_else(|| resolver_path.clone()),
            verified_at: row.verified_at.unwrap_or_else(chrono::Utc::now),
        };
        return Ok((StatusCode::OK, Json(body)).into_response());
    }

    let outcome = state
        .dns_resolver
        .verify_txt(&normalised_domain, &row.challenge_token)
        .await?;
    state.domain_cache.insert(cache_key, outcome.clone()).await;

    match outcome {
        VerifyOutcome::Verified { resolver_path } => {
            let updated = OrgScoped::new(&state.org_idp_domain_repo, org_id)
                .mark_verified(org_idp_id, domain_id, &resolver_path)
                .await?;
            let verified_at = updated.verified_at.unwrap_or_else(chrono::Utc::now);
            state
                .auditor
                .record(AuditEvent::V1(AuditEventV1::new(
                    AuditEventKind::IdpDomainVerified,
                    actor_from(&auth),
                    AuditResource::IdpDomain { domain_id: row.id },
                    auth.correlation_id(),
                    org_id,
                    AuditPayload::new(serde_json::json!({
                        "org_idp_id": org_idp_id,
                        "domain_lower": normalised_domain,
                        "resolver_path": resolver_path,
                    })),
                )))
                .await;
            let body = VerifyDomainResponse {
                id: updated.id,
                domain: updated.domain,
                last_verified_via: resolver_path,
                verified_at,
            };
            Ok((StatusCode::OK, Json(body)).into_response())
        }
        VerifyOutcome::Failed {
            reason,
            resolver_path,
        } => {
            emit_failed_audit(
                state.auditor.as_ref(),
                &auth,
                row.id,
                org_id,
                org_idp_id,
                &normalised_domain,
                resolver_path.as_str(),
                reason.slug(),
            )
            .await;
            Err(IdentityError::DomainVerificationFailed {
                reason: reason.slug(),
            })
        }
    }
}

/// Stable failure-reason slug used by the empty-`challenge_token`
/// branch (pre-migration-020 placeholder rows that never received a
/// real `vrf_*` token). Distinct from the resolver-failure slugs so
/// ops dashboards group it correctly.
const MISSING_CHALLENGE_TOKEN_SLUG: &str = "missing_challenge_token";

/// Emit the `IdpDomainFailed` audit event with the canonical payload
/// shape. Lifted into a helper so the resolver-failure branch and
/// the empty-token branch share one source of truth.
#[allow(clippy::too_many_arguments)]
async fn emit_failed_audit(
    auditor: &dyn zagrosi_core::Auditor,
    auth: &AuthContext,
    domain_row_id: Uuid,
    org_id: Uuid,
    org_idp_id: Uuid,
    domain_lower: &str,
    resolver_path: &str,
    reason_slug: &str,
) {
    auditor
        .record(AuditEvent::V1(AuditEventV1::new(
            AuditEventKind::IdpDomainFailed,
            actor_from(auth),
            AuditResource::IdpDomain {
                domain_id: domain_row_id,
            },
            auth.correlation_id(),
            org_id,
            AuditPayload::new(serde_json::json!({
                "org_idp_id": org_idp_id,
                "domain_lower": domain_lower,
                "resolver_path": resolver_path,
                "reason": reason_slug,
            })),
        )))
        .await;
}

/// Axum handler for `DELETE .../domains/{domain_id}`.
pub async fn delete_domain(
    State(state): State<RoutingState>,
    Extension(auth): Extension<AuthContext>,
    Path((org_slug, org_idp_id, domain_id)): Path<(String, Uuid, Uuid)>,
) -> Result<Response> {
    let org_id = resolve_org_or_404(&state, &org_slug, &auth).await?;

    // `soft_delete` RETURNs the domain string of the row it tombstoned
    // so the audit payload can carry `domain_lower` consistently with
    // create / verify / failed events.
    let removed_domain = OrgScoped::new(&state.org_idp_domain_repo, org_id)
        .soft_delete(org_idp_id, domain_id)
        .await?;
    let Some(domain_lower) = removed_domain else {
        return Err(IdentityError::OrgNotFound);
    };

    state
        .auditor
        .record(AuditEvent::V1(AuditEventV1::new(
            AuditEventKind::IdpDomainDeleted,
            actor_from(&auth),
            AuditResource::IdpDomain { domain_id },
            auth.correlation_id(),
            org_id,
            AuditPayload::new(serde_json::json!({
                "org_idp_id": org_idp_id,
                "domain_lower": domain_lower,
            })),
        )))
        .await;

    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Resolve `org_slug` to its `org_id`, gating on the caller's
/// active-org membership. Cross-tenant probes — slug for org A
/// while `auth.org_id == org B` — surface as
/// [`IdentityError::OrgNotFound`] so the existence of the org is
/// not leaked across tenants.
async fn resolve_org_or_404(
    state: &RoutingState,
    org_slug: &str,
    auth: &AuthContext,
) -> Result<Uuid> {
    let org = state
        .org_repo
        .find_by_slug(org_slug)
        .await?
        .ok_or(IdentityError::OrgNotFound)?;
    if org.id != auth.org_id() {
        return Err(IdentityError::OrgNotFound);
    }
    Ok(org.id)
}

/// Lift the caller's [`AuthContext`] into the [`zagrosi_core::AuditActor`]
/// shape. The audit event records the actor's user id (no IP — that
/// belongs at the gateway middleware layer alongside the
/// `axum::extract::ConnectInfo` source).
const fn actor_from(auth: &AuthContext) -> zagrosi_core::AuditActor {
    zagrosi_core::AuditActor::User {
        user_id: auth.subject_id(),
        ip: None,
    }
}

/// Normalise a raw domain to ASCII-lowercase via IDNA. Public to
/// the routing module so the discover handler can share the same
/// rule.
///
/// Uses [`idna::domain_to_ascii_strict`] which applies UTS46 strict
/// transitional processing AND enforces the DNS label / total-length
/// limits + rejects ASCII control bytes (CR, LF, NUL, tab, etc.).
/// The lax `domain_to_ascii` would silently accept embedded NUL or
/// per-label > 63 octets (RFC 1035 violation), opening response-
/// splitting / log-injection / FQDN-construction surfaces.
pub(crate) fn normalise_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(IdentityError::InvalidDomain {
            reason: "empty domain".into(),
        });
    }
    let ascii =
        idna::domain_to_ascii_strict(trimmed).map_err(|err| IdentityError::InvalidDomain {
            reason: format!("idna strict failure: {err}"),
        })?;
    let lower = ascii.to_ascii_lowercase();
    // Defensive: domains MUST contain at least one `.` (FQDN) and
    // be no longer than 253 octets per RFC 1035 §2.3.4. Local-only
    // names like `mailhog` cannot route anywhere and would only
    // confuse downstream consumers.
    if !lower.contains('.') || lower.len() > 253 {
        return Err(IdentityError::InvalidDomain {
            reason: format!("`{lower}` is not a valid public FQDN"),
        });
    }
    Ok(lower)
}

/// Reserved for the rare call-site that needs to coerce a domain
/// id without going through the path extractor (e.g. tests).
#[doc(hidden)]
pub fn parse_uuid(raw: &str) -> Result<Uuid> {
    Uuid::from_str(raw).map_err(|_| IdentityError::InvalidDomain {
        reason: "invalid uuid".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_domain_lowercases_and_idns() {
        let n = normalise_domain("BÜCHER.example").unwrap_or_else(|e| panic!("normalise: {e}"));
        assert_eq!(n, "xn--bcher-kva.example");
    }

    #[test]
    fn normalise_domain_rejects_empty() {
        assert!(matches!(
            normalise_domain("").unwrap_err(),
            IdentityError::InvalidDomain { .. }
        ));
    }

    #[test]
    fn normalise_domain_rejects_local_label() {
        assert!(matches!(
            normalise_domain("mailhog").unwrap_err(),
            IdentityError::InvalidDomain { .. }
        ));
    }

    #[test]
    fn normalise_domain_rejects_oversized() {
        let long = format!("{}.example", "a".repeat(260));
        assert!(matches!(
            normalise_domain(&long).unwrap_err(),
            IdentityError::InvalidDomain { .. }
        ));
    }
}
