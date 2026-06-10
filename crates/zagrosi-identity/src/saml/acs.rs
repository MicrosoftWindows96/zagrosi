// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! ACS handler — strict-order SAML response validation.
//!
//! Section-11 spec lines 140-178 enumerate the contract; the
//! implementation here lifts the heavy lifting into samael's
//! `parse_xml_response_with_mode` (signature verify + XSW reduction +
//! audience / window / Bearer / Recipient / `InResponseTo` checks)
//! and adds the domain-specific guards samael does not provide:
//!
//! ```text
//!   0. IdP-initiated rejected unless `allow_idp_initiated == true`
//!      (samael honours this when it sees the `Response`).
//!   1. XML parse — DTD off, external entities off (samael wraps
//!      libxml2's hardened parser).
//!   2. Signature verify against `idp_x509_cert_pem`. Reject duplicate
//!      `xml:id` (samael's `Crypto::reduce_xml_to_signed`).
//!   3. Signed-node-only extraction (`ReduceMode::ValidateAndMarkNoAncestors`).
//!   4. Decrypt assertion if encrypted (RSA-OAEP-MGF1P / RSA-1.5 key
//!      wrap; AES128-CBC / AES128-GCM data; AES-256-GCM rejected).
//!   5. Bearer subject confirmation (method = bearer, recipient =
//!      ACS URL, NotOnOrAfter > now, InResponseTo = persisted id).
//!   6. Conditions (audience contains SP entity id; NotBefore /
//!      NotOnOrAfter window valid).
//!   7. Replay: INSERT saml_assertion_replay; UNIQUE → reject.
//!   8. RelayState: matches persisted row; mark used_at.
//!   9. Attribute mapping per per-IdP overrides.
//!  10. User resolution via federated_identities; JIT or anchor-hit.
//!  11. Issue session (NEVER reads existing cookie; SameSite=Lax +
//!      cross-site POST is the threat).
//! ```
//!
//! Steps 7-11 happen inside a single sqlx transaction so a crash mid-
//! flow either commits the entire ACS payload or rolls everything back.
//! The session-issue call (step 11) runs **outside** the transaction —
//! it uses a separate insert path under `sessions` and the `IssueSession`
//! handler already owns its own retry-safe semantics.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use samael::crypto::ReduceMode;
use samael::metadata::{EntityDescriptor, IdpSsoDescriptor, KeyDescriptor};
use samael::schema::Assertion;
use samael::service_provider::{Error as SamaelError, ServiceProvider};
use uuid::Uuid;

use crate::crypto::Secrets;
use crate::error::IdentityError;
use crate::repo::{
    FederatedIdentityRepo, MembershipRepo, NewSamlAssertion, OrgIdpRepo, OrgRepo, OrgScoped,
    SamlPendingRepo, SamlReplayRepo, UserRepo, with_org_context,
};
use crate::session::{IdentitySessionIssuer, SessionAttachment};

use super::attribute::{self, MappedAttributes};
use super::authn;
use super::config::SamlConfigV1;
use super::errors::SamlError;
use super::jit::{PROTOCOL, SamlJitInput, SamlJitOutcome, SamlJitProvisioner};

/// AuthnContextClassRef → `acr` mapping. SAML's
/// `AuthnContext/AuthnContextClassRef` is the closest analogue to
/// OIDC's `acr` claim; we surface it verbatim on the issued session.
const AUTHN_METHOD: &str = "saml";

/// SAML 2.0 transient NameID format URI. The transient format
/// re-rolls per session — using it as the federated-identity anchor
/// `sub` produces a fresh anchor on every login (JIT loop) and, if
/// the IdP ever re-issues an identical transient string later,
/// allows impersonation. Reject explicitly.
const NAMEID_FORMAT_TRANSIENT_V2: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
/// SAML 1.1 transient NameID format URI (legacy alias). Reject for
/// the same reasons as the V2 form.
const NAMEID_FORMAT_TRANSIENT_V1: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:transient";

/// Composed dependency bundle for [`handler`].
#[derive(Clone)]
pub struct AcsDeps {
    /// Org lookup (slug → row).
    pub orgs: OrgRepo,
    /// IdP lookup + config update path.
    pub idps: OrgIdpRepo,
    /// SAML pending-auth ledger persistence.
    pub pending: SamlPendingRepo,
    /// Replay-once ledger persistence.
    pub replay: SamlReplayRepo,
    /// User lookup + JIT insert.
    pub users: UserRepo,
    /// Federated-identity (`(protocol, iss, sub)`) anchor.
    pub federated: FederatedIdentityRepo,
    /// Membership lookup + JIT insert.
    pub memberships: MembershipRepo,
    /// JIT provisioner (composed from users + federated + memberships).
    pub jit: SamlJitProvisioner,
    /// Session issuer (mints `sid_*` + CSRF).
    pub session_issuer: Arc<IdentitySessionIssuer>,
    /// Section-04 secrets shim (for SP signing-key decrypt on encrypted
    /// assertion paths; held for parity with [`super::metadata::MetadataDeps`]).
    pub secrets: Arc<Secrets>,
    /// Public base URL (`ZAGROSI_BASE_URL`).
    pub base_url: Arc<str>,
    /// Connection pool — the ACS handler opens the replay + relay-mark
    /// + JIT transaction here.
    pub pool: sqlx::PgPool,
}

/// Inbound form payload posted by the IdP. Both fields are required
/// by the SAML 2.0 HTTP-POST binding.
#[derive(Debug, Clone)]
pub struct AcsRequest {
    /// `SAMLResponse` form field — base64-encoded `<saml:Response>`
    /// XML.
    pub saml_response_b64: String,
    /// `RelayState` form field — opaque value the SP minted on the
    /// AuthnRequest start path. The ACS handler matches against the
    /// persisted `saml_pending_auth.relay_state`.
    pub relay_state: String,
}

/// Outcome of a successful ACS run.
#[derive(Debug, Clone)]
pub struct AcsOutcome {
    /// User id of the issued session subject.
    pub user_id: Uuid,
    /// Org id of the issued session subject.
    pub org_id: Uuid,
    /// Session id of the issued session.
    pub session_id: Uuid,
    /// SAML assertion id consumed (replay-ledger key).
    pub assertion_id: String,
    /// Session cookies (`__Host-zagrosi_sid` + `__Host-zagrosi_csrf`)
    /// the gateway stamps on the response.
    pub attachment: SessionAttachment,
}

/// Run the ACS path.
///
/// # Errors
///
/// Every variant of [`SamlError`] is reachable from this path; see
/// the strict-order checklist in the module docstring for the
/// mapping. The HTTP layer collapses every variant onto a uniform
/// 401 / 409 surface so timing differences do not leak which step
/// rejected the assertion.
#[tracing::instrument(
    skip_all,
    fields(
        org_slug = %org_slug,
        route = "saml.acs",
    )
)]
pub async fn handler(
    deps: &AcsDeps,
    org_slug: &str,
    request: &AcsRequest,
) -> Result<AcsOutcome, SamlError> {
    // Step A: resolve org + IdP + revalidate config.
    let (org_id, idp, cfg) = resolve_idp(deps, org_slug).await?;

    // Step B: decode the base64 envelope. Reject DTD/external-entity
    // payloads pre-flight — samael's libxml2 wrapper rejects them too,
    // but a pre-flight string scan gives us a typed audit reason
    // (samael collapses XXE attempts into `FailedToValidateSignature`
    // or `FailedToParseSamlResponse`, neither of which renders the
    // attack class clearly).
    let xml = decode_response_xml(&request.saml_response_b64)?;
    reject_dtd_or_external_entity(&xml)?;

    // Step C: build the samael ServiceProvider with the IdP cert
    // populated so the parse path can verify the signature.
    let acs_url = authn::derive_acs_url(&deps.base_url, org_slug);
    let entity_id = authn::derive_entity_id(&deps.base_url);
    let sp = build_sp_for_acs(&cfg, &acs_url, &entity_id)?;

    // Step D: open the orchestration transaction. The pending lookup
    // must run inside the same tx as the replay insert + JIT writes
    // + session insert so the entire ACS payload commits or rolls
    // back atomically.
    let mut tx = deps
        .pool
        .begin()
        .await
        .map_err(|err| internal_error("tx begin", &err.to_string()))?;

    // Set the `app.org_id` GUC so the RLS layer (section-05's
    // policies) can refuse rows whose `org_id` does not match.
    // Mirrors the OIDC service callback.
    with_org_context(&mut tx, org_id)
        .await
        .map_err(|err| internal_error("with_org_context", &err.to_string()))?;

    // Step E: claim the pending row by `RelayState` under a row
    // lock. The lock serialises concurrent ACS posts that share a
    // `RelayState`: the first caller takes the lock + commits the
    // mark-used; concurrent posts wait, then re-read the committed
    // `used_at IS NOT NULL` state and reject with
    // `RelayStateMismatch`. Without the lock, a forged second
    // response carrying a distinct `assertion_id` for the same
    // `RelayState` could pass samael in parallel and slip past the
    // `saml_assertion_replay` UNIQUE constraint.
    let pending = deps
        .pending
        .find_by_relay_state_for_update_in_tx(&mut tx, &request.relay_state)
        .await
        .map_err(|err| repo_error(&err))?
        .ok_or(SamlError::RelayStateMismatch)?;
    // Bind `now` AFTER the lock returns. Concurrent ACS posts
    // serialise on the row lock; binding `now` before the wait
    // would carry a stale wall-clock through a long lock-grant
    // window, accepting rows that expired during the wait. The
    // post-lock `now` is the authoritative reference for the
    // expires_at + mark_used + JIT timestamps below.
    let now = Utc::now();
    if pending.used_at.is_some() {
        return Err(SamlError::AssertionReplay);
    }
    if pending.expires_at <= now {
        // The 10-minute pending-row TTL has elapsed (spec line 60).
        // The cleanup worker may not have reached this row yet —
        // enforce the deadline at the security boundary so a stolen
        // `RelayState` cannot be replayed hours after capture.
        return Err(SamlError::RelayStateMismatch);
    }
    if pending.org_idp_id != idp.id {
        // The relay row points at a different IdP than the org_slug
        // resolved — a forged relay attempting to cross the IdP
        // boundary. Rejected with the same surface as a missing row.
        return Err(SamlError::RelayStateMismatch);
    }

    // Step F: hand off to samael. Steps 1-6 of the strict order
    // happen inside this call; failures are mapped onto SamlError
    // variants below. Pin `ReduceMode::ValidateAndMarkNoAncestors`
    // explicitly so a future samael bump that flips the default
    // cannot silently weaken the XSW posture (spec invariant 4).
    let possible_request_ids: [&str; 1] = [pending.request_id.as_str()];
    let assertion = sp
        .parse_xml_response_with_mode(
            &xml,
            Some(&possible_request_ids[..]),
            ReduceMode::ValidateAndMarkNoAncestors,
        )
        .map_err(|err| map_samael_error(&err))?;

    // Step F.1: explicit Conditions + AudienceRestriction guard.
    // samael's `validate_assertion` only checks NotBefore /
    // NotOnOrAfter / AudienceRestriction WHEN THEY ARE PRESENT
    // (samael service_provider/mod.rs:528). An assertion with no
    // `<Conditions>` block at all passes samael's validator — so
    // we reject explicitly, otherwise the audience invariant
    // (spec invariant 6) is silently bypassed.
    require_conditions_and_audience(&assertion)?;

    // Step G: extract the assertion id + NotOnOrAfter for the replay
    // ledger. Both are mandatory; their absence indicates a
    // malformed assertion samael accepted (extremely defensive — but
    // we are auditing every step).
    let assertion_id = assertion_id_owned(&assertion)?;
    let not_on_or_after = assertion_not_on_or_after(&assertion)?;

    // Step H: replay-once. The composite primary key
    // `(org_idp_id, assertion_id)` IS the rejection mechanism.
    deps.replay
        .insert_in_tx(
            &mut tx,
            NewSamlAssertion {
                org_idp_id: idp.id,
                assertion_id: &assertion_id,
                not_on_or_after,
            },
        )
        .await
        .map_err(|err| match err {
            IdentityError::AssertionReplay => SamlError::AssertionReplay,
            other => repo_error(&other),
        })?;

    // Step I: mark the pending row consumed inside the same tx.
    // `now` was bound at the top of the orchestration; reuse it so
    // the lifetime semantics (`expires_at > now`) and the mark-used
    // stamp share a single temporal reference point.
    deps.pending
        .mark_used(&mut tx, pending.id, now)
        .await
        .map_err(|err| match err {
            IdentityError::TokenNotFound => SamlError::AssertionReplay,
            other => repo_error(&other),
        })?;

    // Step J: attribute mapping over the validated assertion.
    let attrs = attribute::map_attributes(&assertion, &cfg.attribute_mapping);
    let nameid = nameid_value(&assertion)?;

    // Step K: resolve the SSO anchor.
    let (user_id, anchor_id) = resolve_user(
        deps,
        &mut tx,
        &cfg,
        org_id,
        idp.id,
        &cfg.idp_entity_id,
        &nameid,
        &attrs,
        now,
    )
    .await?;

    // Step L: bump `last_login_at` on the anchor inside the tx.
    deps.jit
        .federated_update_last_login_in_tx(&mut tx, anchor_id, now)
        .await?;

    // Step M: issue the fresh session inside the same tx. The
    // cookie pair returned here overwrites any inbound
    // `__Host-zagrosi_sid` — the threat model for SAML ACS is
    // "browser POSTs cross-site with stale cookie", so we never
    // read inbound credentials.
    //
    // Issuing the session BEFORE `tx.commit()` is required for
    // atomicity: a session-row insert failure on the
    // post-commit path used to leave a JIT-provisioned user with
    // a consumed replay row but no session, locking that user
    // out for the assertion. With the in-tx variant the entire
    // ACS payload commits or rolls back as a single unit.
    let amr_refs: [&str; 1] = [AUTHN_METHOD];
    let acr = authn_context_class_ref(&assertion);
    let (issued, attachment) = deps
        .session_issuer
        .issue_with_attachment_in_tx(&mut tx, user_id, Some(org_id), &amr_refs, acr.as_deref())
        .await
        .map_err(|err| internal_error("session issue", &err.to_string()))?;

    tx.commit()
        .await
        .map_err(|err| internal_error("tx commit", &err.to_string()))?;

    Ok(AcsOutcome {
        user_id,
        org_id,
        session_id: issued.id,
        assertion_id,
        attachment,
    })
}

/// Resolve `org_slug` → `(org_id, org_idp, SamlConfigV1)`.
async fn resolve_idp(
    deps: &AcsDeps,
    org_slug: &str,
) -> Result<(Uuid, crate::domain::OrgIdp, SamlConfigV1), SamlError> {
    let org = deps
        .orgs
        .find_by_slug(org_slug)
        .await
        .map_err(|err| repo_error(&err))?
        .ok_or(SamlError::OrgNotFound)?;

    let scoped = OrgScoped::new(&deps.idps, org.id);
    let mut saml_idps: Vec<_> = scoped
        .list_for_org()
        .await
        .map_err(|err| repo_error(&err))?
        .into_iter()
        .filter(|idp| idp.enabled && idp.protocol == PROTOCOL)
        .collect();
    if saml_idps.is_empty() {
        return Err(SamlError::IdpNotFound);
    }
    if saml_idps.len() > 1 {
        return Err(SamlError::AmbiguousIdp);
    }
    let idp = saml_idps.remove(0);
    let cfg = SamlConfigV1::from_jsonb(&idp.config)?;
    Ok((org.id, idp, cfg))
}

/// Decode the form-posted `SAMLResponse` field. The HTTP-POST binding
/// uses STANDARD base64 encoding (not URL-safe). Reject anything that
/// fails to decode rather than handing it to samael — samael only
/// surfaces `FailedToParseSamlResponse`, which would shadow the more
/// specific reason.
fn decode_response_xml(b64: &str) -> Result<String, SamlError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let bytes = STANDARD.decode(b64.as_bytes()).map_err(|_| {
        tracing::trace!(target: "zagrosi.identity.saml", "saml response base64 decode failed");
        SamlError::XmlParseFailed
    })?;
    let xml = String::from_utf8(bytes).map_err(|_| {
        tracing::trace!(target: "zagrosi.identity.saml", "saml response not valid utf-8");
        SamlError::XmlParseFailed
    })?;
    Ok(xml)
}

/// Pre-flight DTD / external-entity scan. The XML payload may not
/// contain a DOCTYPE declaration nor an `ENTITY` definition — both
/// are XXE pre-conditions and SAML never legitimately uses either.
///
/// The scan covers the WHOLE document (a previous 4 KiB head bound
/// allowed an attacker to push a malicious DOCTYPE past byte 4096
/// behind a long XML comment prologue). The cost over the full
/// payload is sub-millisecond — orders of magnitude cheaper than
/// the libxml2 parse it gates.
fn reject_dtd_or_external_entity(xml: &str) -> Result<(), SamlError> {
    if xml.contains("<!DOCTYPE") || xml.contains("<!doctype") {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_dtd_rejected",
            "saml response carries DOCTYPE — XXE pre-condition rejected"
        );
        return Err(SamlError::DtdRejected);
    }
    if xml.contains("<!ENTITY") || xml.contains("<!entity") {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_external_entity_rejected",
            "saml response carries ENTITY declaration — XXE pre-condition rejected"
        );
        return Err(SamlError::ExternalEntityRejected);
    }
    Ok(())
}

/// Defense-in-depth audience guard. samael's `validate_assertion`
/// checks `Conditions/AudienceRestriction` only when both
/// `<Conditions>` AND its `<AudienceRestriction>` child are present
/// — an assertion with no `<Conditions>` block at all bypasses the
/// audience invariant entirely. Spec invariant 6 mandates the SP
/// entity id appear in the audience list; we enforce here so a
/// malformed-but-signed assertion cannot land a session against the
/// wrong audience.
///
/// We additionally walk EACH `AudienceRestriction` and reject when
/// any one carries an empty audience Vec. samael's content check
/// uses `iter().any()` which returns false on empty (rejecting
/// correctly today), but pinning the invariant here means a future
/// samael bug that flips the `any()` semantics cannot bypass our
/// audience invariant.
fn require_conditions_and_audience(assertion: &Assertion) -> Result<(), SamlError> {
    let Some(conditions) = &assertion.conditions else {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_conditions_missing",
            "saml assertion missing Conditions element"
        );
        return Err(SamlError::ConditionsWindowInvalid);
    };
    let Some(audience_restrictions) = &conditions.audience_restrictions else {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_audience_missing",
            "saml assertion Conditions missing AudienceRestriction"
        );
        return Err(SamlError::AudienceMismatch);
    };
    if audience_restrictions.is_empty() {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_audience_empty",
            "saml assertion AudienceRestriction list is empty"
        );
        return Err(SamlError::AudienceMismatch);
    }
    for restriction in audience_restrictions {
        if restriction.audience.is_empty() {
            tracing::warn!(
                target: "zagrosi.identity.saml",
                audit = "saml_acs_audience_inner_empty",
                "saml assertion AudienceRestriction inner audience list is empty"
            );
            return Err(SamlError::AudienceMismatch);
        }
    }
    Ok(())
}

/// Build the samael [`ServiceProvider`] for ACS validation. The IdP
/// cert is published into `idp_metadata.idp_sso_descriptors[0]
/// .key_descriptors[0]` so samael's `idp_signing_certs()` can pick
/// it up.
fn build_sp_for_acs(
    cfg: &SamlConfigV1,
    acs_url: &str,
    entity_id: &str,
) -> Result<ServiceProvider, SamlError> {
    let cert_b64 = pem_certificate_body(&cfg.idp_x509_cert_pem)?;
    let key_descriptor = KeyDescriptor {
        key_use: Some("signing".to_owned()),
        key_info: samael::key_info::KeyInfo {
            id: None,
            x509_data: Some(samael::key_info::X509Data {
                certificates: vec![cert_b64],
            }),
        },
        encryption_methods: None,
    };
    let idp_descriptor = IdpSsoDescriptor {
        id: None,
        valid_until: None,
        cache_duration: None,
        protocol_support_enumeration: None,
        error_url: None,
        signature: None,
        key_descriptors: vec![key_descriptor],
        organization: None,
        contact_people: Vec::new(),
        artifact_resolution_service: Vec::new(),
        single_logout_services: Vec::new(),
        manage_name_id_services: Vec::new(),
        name_id_formats: Vec::new(),
        want_authn_requests_signed: None,
        single_sign_on_services: Vec::new(),
        name_id_mapping_services: Vec::new(),
        assertion_id_request_services: Vec::new(),
        attribute_profiles: Vec::new(),
        attributes: Vec::new(),
    };
    let idp_metadata = EntityDescriptor {
        entity_id: Some(cfg.idp_entity_id.clone()),
        idp_sso_descriptors: Some(vec![idp_descriptor]),
        ..EntityDescriptor::default()
    };
    Ok(ServiceProvider {
        entity_id: Some(entity_id.to_owned()),
        acs_url: Some(acs_url.to_owned()),
        slo_url: None,
        idp_metadata,
        allow_idp_initiated: cfg.allow_idp_initiated,
        ..ServiceProvider::default()
    })
}

/// Strip PEM markers and concatenate the base64 body. samael accepts
/// the raw base64 (no `BEGIN/END CERTIFICATE` markers) inside
/// `<X509Certificate>`. The SP pins exactly one IdP cert.
///
/// Three guards:
///
/// 1. EXACT PEM-type match: only `BEGIN CERTIFICATE` / `END CERTIFICATE`
///    are accepted. Variants such as `BEGIN TRUSTED CERTIFICATE`,
///    `BEGIN PRIVATE KEY`, `BEGIN PUBLIC KEY`, `BEGIN PKCS7` are
///    rejected. Without this, a `find("-----BEGIN CERTIFICATE")`
///    substring scan could be tricked by typed PEM blobs that share
///    the same prefix.
/// 2. Multi-cert rejection: a second `BEGIN CERTIFICATE` after the
///    first means the admin uploaded a chain. The SP layer pins ONE
///    IdP cert; ambiguity here picks an arbitrary cert and breaks
///    signature verification opaquely downstream.
/// 3. Base64 round-trip: the cleaned body MUST decode as base64
///    so a typo or truncated upload surfaces as a typed error
///    rather than silently propagating to xmlsec.
fn pem_certificate_body(pem: &str) -> Result<String, SamlError> {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    // Reject typed PEM blobs (`BEGIN TRUSTED CERTIFICATE`,
    // `BEGIN PRIVATE KEY`, `BEGIN PKCS7`, etc.). These would slip
    // past a substring `find(BEGIN)` because the BEGIN literal
    // above is a strict prefix of `BEGIN TRUSTED CERTIFICATE-----`.
    // Walk every `-----BEGIN ` occurrence and confirm the type
    // token is exactly `CERTIFICATE`.
    for match_idx in pem.match_indices("-----BEGIN ").map(|(idx, _)| idx) {
        let after_prefix = &pem[match_idx + "-----BEGIN ".len()..];
        let Some(dashes) = after_prefix.find("-----") else {
            return Err(SamlError::ConfigInvalid {
                reason: "idp_x509_cert_pem BEGIN line lacks closing dashes".to_owned(),
            });
        };
        let pem_type = &after_prefix[..dashes];
        if pem_type != "CERTIFICATE" {
            return Err(SamlError::ConfigInvalid {
                reason: format!(
                    "idp_x509_cert_pem must contain a CERTIFICATE PEM block, found `{pem_type}`"
                ),
            });
        }
    }

    let begin = pem.find(BEGIN);
    let end = pem.find(END);
    let (Some(b), Some(e)) = (begin, end) else {
        return Err(SamlError::ConfigInvalid {
            reason: "idp_x509_cert_pem missing BEGIN/END markers".to_owned(),
        });
    };
    if e <= b {
        return Err(SamlError::ConfigInvalid {
            reason: "idp_x509_cert_pem markers in wrong order".to_owned(),
        });
    }

    // Reject multi-cert bundles: a second `BEGIN CERTIFICATE` after
    // the first means the admin uploaded a chain.
    let after_first = &pem[e + END.len()..];
    if after_first.contains(BEGIN) {
        return Err(SamlError::ConfigInvalid {
            reason: "idp_x509_cert_pem must contain exactly one certificate".to_owned(),
        });
    }

    let body = &pem[b + BEGIN.len()..e];
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(SamlError::ConfigInvalid {
            reason: "idp_x509_cert_pem body empty after strip".to_owned(),
        });
    }
    // Round-trip the base64 body so a corrupted upload fails fast
    // with a typed reason instead of propagating to xmlsec's cert
    // parser as an opaque crypto error.
    if base64::Engine::decode(&BASE64_STANDARD, &cleaned).is_err() {
        return Err(SamlError::ConfigInvalid {
            reason: "idp_x509_cert_pem body is not valid base64".to_owned(),
        });
    }
    Ok(cleaned)
}

/// Resolve `(user_id, anchor_id)` from the validated assertion.
/// Anchor-hit path bumps last-login; miss path runs JIT inside the
/// caller's transaction.
#[allow(clippy::too_many_arguments)]
async fn resolve_user(
    deps: &AcsDeps,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cfg: &SamlConfigV1,
    org_id: Uuid,
    org_idp_id: Uuid,
    idp_entity_id: &str,
    nameid: &str,
    attrs: &MappedAttributes,
    now: DateTime<Utc>,
) -> Result<(Uuid, Uuid), SamlError> {
    let existing = deps
        .federated
        .find_by_protocol_iss_sub_in_tx(tx, PROTOCOL, idp_entity_id, nameid)
        .await
        .map_err(|err| repo_error(&err))?;

    if let Some(anchor) = existing {
        // Cross-tenant defence: an anchor minted under a DIFFERENT
        // IdP that happens to share `(protocol, iss, sub)` with the
        // resolving IdP must not bind a session here. The OIDC
        // service runs the same guard at oidc/service.rs (`existing
        // .org_idp_id != idp.id`). Without this check, a SAML IdP
        // re-registered under a fresh org row could pick up an
        // anchor from the prior registration and silently auth its
        // owner into the new tenant.
        if anchor.org_idp_id != org_idp_id {
            tracing::warn!(
                target: "zagrosi.identity.saml",
                audit = "saml_acs_anchor_cross_tenant",
                anchor_org_idp_id = %anchor.org_idp_id,
                resolved_org_idp_id = %org_idp_id,
                "saml anchor org_idp_id mismatch — cross-tenant rejected"
            );
            return Err(SamlError::CrossTenantAnchor);
        }

        // Tombstoned anchor (legitimate IdP, tombstoned by admin).
        let Some(uid) = anchor.user_id else {
            return Err(SamlError::AccountAlreadyExists);
        };

        // Linked user must still be live.
        deps.users
            .find_by_id_in_tx(tx, uid)
            .await
            .map_err(|err| repo_error(&err))?
            .ok_or(SamlError::AccountAlreadyExists)?;

        // Live membership in the org the slug resolved to.
        deps.memberships
            .find_for_user_org_in_tx(tx, uid, org_id)
            .await
            .map_err(|err| repo_error(&err))?
            .ok_or(SamlError::AccountAlreadyExists)?;

        return Ok((uid, anchor.id));
    }

    // JIT path. The trust gate + cross-org collision guard live
    // inside [`SamlJitProvisioner::run`].
    let email = attrs
        .email
        .clone()
        .ok_or(SamlError::SubjectConfirmationInvalid)?;
    let display_name = attrs.display_name();
    let outcome: SamlJitOutcome = deps
        .jit
        .run(
            tx,
            SamlJitInput {
                org_id,
                org_idp_id,
                issuer: idp_entity_id.to_owned(),
                subject: nameid.to_owned(),
                email: email.clone(),
                email_lower: email,
                display_name,
                trust_email_assertion: cfg.trust_email_assertion,
                default_role: cfg.default_role.clone(),
            },
            now,
        )
        .await?;
    Ok((outcome.user.id, outcome.anchor.id))
}

/// Lift the assertion `ID` attribute onto the heap so the replay-ledger
/// insert can borrow it across an `await` boundary without a borrow
/// of the `Assertion` itself (which gets moved into the attribute
/// mapping).
fn assertion_id_owned(assertion: &Assertion) -> Result<String, SamlError> {
    if assertion.id.is_empty() {
        return Err(SamlError::SubjectConfirmationInvalid);
    }
    Ok(assertion.id.clone())
}

/// Lift the assertion `Conditions/@NotOnOrAfter` (or the bearer
/// `SubjectConfirmationData/@NotOnOrAfter` as fallback) for the
/// replay-ledger TTL row. samael has already validated the window;
/// we only need the value for the ledger.
fn assertion_not_on_or_after(assertion: &Assertion) -> Result<DateTime<Utc>, SamlError> {
    if let Some(conditions) = &assertion.conditions
        && let Some(noo) = conditions.not_on_or_after
    {
        return Ok(noo);
    }
    if let Some(subject) = &assertion.subject
        && let Some(confs) = &subject.subject_confirmations
    {
        for conf in confs {
            if let Some(data) = &conf.subject_confirmation_data
                && let Some(noo) = data.not_on_or_after
            {
                return Ok(noo);
            }
        }
    }
    // No NotOnOrAfter on Conditions or any bearer
    // SubjectConfirmationData. samael's own validator would have
    // rejected the assertion before reaching this fn (samael's
    // `validate_assertion_subject_confirmation` requires
    // `SubjectConfirmationData`); reaching here is malformed input
    // we surface rather than substituting an arbitrary clock value.
    Err(SamlError::ConditionsWindowInvalid)
}

/// Lift the `Subject/NameID/@Value`. Empty values are rejected — the
/// federated-identity anchor needs a non-empty `sub`.
///
/// `transient` NameID format is rejected explicitly. A transient
/// NameID re-rolls per session; using it as the anchor `sub` would
/// create a fresh `federated_identities` row on every login (JIT
/// loop) and, if the IdP later re-issues an identical transient
/// string, would let the new session inherit the prior user's
/// identity. Section-11 spec invariant 7 requires a stable
/// `(protocol, iss, sub)` anchor; transient violates that contract.
fn nameid_value(assertion: &Assertion) -> Result<String, SamlError> {
    let subject = assertion
        .subject
        .as_ref()
        .ok_or(SamlError::SubjectConfirmationInvalid)?;
    let nameid = subject
        .name_id
        .as_ref()
        .ok_or(SamlError::SubjectConfirmationInvalid)?;
    if nameid.value.is_empty() {
        return Err(SamlError::SubjectConfirmationInvalid);
    }
    // SAML Core 8.3.1 says a missing `Format` defaults to
    // `unspecified`, whose semantics are IdP-defined and therefore
    // unstable for SSO-anchor purposes. We require an EXPLICIT,
    // stable format URI; a `None` Format is rejected to match the
    // transient-format rejection's anchor-stability rationale.
    let Some(format) = &nameid.format else {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_nameid_format_missing",
            "saml assertion NameID missing Format attribute — rejected (anchor instability)"
        );
        return Err(SamlError::SubjectConfirmationInvalid);
    };
    if format == NAMEID_FORMAT_TRANSIENT_V1 || format == NAMEID_FORMAT_TRANSIENT_V2 {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            audit = "saml_acs_transient_nameid_rejected",
            format = %format,
            "saml assertion NameID format is transient — rejected (anchor instability)"
        );
        return Err(SamlError::SubjectConfirmationInvalid);
    }
    Ok(nameid.value.clone())
}

/// Lift the first `AuthnContextClassRef` if present. Used as the
/// `acr` value on the issued session.
fn authn_context_class_ref(assertion: &Assertion) -> Option<String> {
    let stmts = assertion.authn_statements.as_ref()?;
    for stmt in stmts {
        if let Some(ctx) = &stmt.authn_context
            && let Some(class_ref) = &ctx.value
            && let Some(value) = &class_ref.value
            && !value.is_empty()
        {
            return Some(value.clone());
        }
    }
    None
}

/// Map a samael [`SamaelError`] onto the [`SamlError`] surface. Each
/// branch picks the most specific audit reason; everything else
/// collapses onto `SignatureInvalid` (the closest "unspecified"
/// reject for the SAML public surface).
fn map_samael_error(err: &SamaelError) -> SamlError {
    use SamaelError as S;
    let variant = match err {
        S::DestinationValidationError { .. } | S::AssertionRecipientMismatch { .. } => {
            SamlError::RecipientMismatch
        }
        S::AssertionExpired { .. }
        | S::AssertionSubjectConfirmationExpired { .. }
        | S::AssertionConditionExpired { .. }
        | S::ResponseExpired { .. } => SamlError::NotOnOrAfterExpired,
        S::AssertionSubjectConfirmationExpiredBefore { .. }
        | S::AssertionConditionExpiredBefore { .. } => SamlError::NotBeforeInFuture,
        S::AssertionConditionAudienceRestrictionFailed { .. } => SamlError::AudienceMismatch,
        S::AssertionBearerSubjectConfirmationMissing | S::AssertionSubjectConfirmationMissing => {
            SamlError::SubjectConfirmationInvalid
        }
        S::AssertionInResponseToInvalid { .. } | S::ResponseInResponseToInvalid { .. } => {
            SamlError::InResponseToMismatch
        }
        S::AssertionIssuerMismatch { .. } | S::ResponseIssuerMismatch { .. } => {
            SamlError::IssuerMismatch
        }
        S::ResponseBadStatusCode { .. }
        | S::FailedToValidateSignature
        | S::FailedToParseCert { .. }
        | S::CryptoXmlError(_)
        | S::CryptoProviderError(_)
        | S::UnexpectedError => SamlError::SignatureInvalid,
        S::FailedToParseSamlResponse(_)
        | S::FailedToParseSamlAssertion(_)
        | S::DeserializeResponseError => SamlError::XmlParseFailed,
        S::EncryptedAssertionsNotYetSupported
        | S::EncryptedAssertionKeyMethodUnsupported { .. }
        | S::EncryptedAssertionValueMethodUnsupported { .. }
        | S::EncryptedAssertionInvalid
        | S::FailedToDecryptAssertion
        | S::MissingEncryptedKeyInfo
        | S::MissingEncryptedValueInfo
        | S::MissingPrivateKeySP
        | S::UnsupportedKey => SamlError::EncryptionMethodUnsupported,
        S::MissingAcsUrl | S::MissingSloUrl => SamlError::Internal,
    };
    tracing::warn!(
        target: "zagrosi.identity.saml",
        audit = ?variant.sub_reason(),
        "saml acs samael error mapped"
    );
    variant
}

/// Map a repo-layer [`IdentityError`] onto the SAML error surface.
fn repo_error(err: &IdentityError) -> SamlError {
    tracing::warn!(target: "zagrosi.identity.saml", error = %err, "saml acs: repo error");
    SamlError::Internal
}

/// Internal-fault helper. Renders a uniform `SamlError::Internal` and
/// captures the diagnostic at warn level.
fn internal_error(stage: &'static str, detail: &str) -> SamlError {
    tracing::warn!(
        target: "zagrosi.identity.saml",
        stage,
        %detail,
        "saml acs: internal error"
    );
    SamlError::Internal
}

/// Fuzz entry point for the SAML ACS XML pre-flight + parser
/// surface. The function consumes arbitrary bytes, treats them as
/// either a base64-encoded `<saml:Response>` payload OR a raw XML
/// document, and drives the bytes through:
///
/// 1. base64 decode (fail-soft for the raw-bytes path).
/// 2. UTF-8 validation.
/// 3. Whole-document DTD / external-entity pre-flight rejection.
/// 4. samael's `parse_xml_response_with_mode` (pinned at
///    `ReduceMode::ValidateAndMarkNoAncestors` — same mode the prod
///    handler uses) against a synthetic SP with empty IdP metadata.
///    With no signing certs, samael skips cryptographic verification
///    and exercises the libxml2 + xmlsec XML decoder + reducer paths
///    — the XSW + XXE attack surface.
///
/// # Invariants
///
/// - No panic on any input (workspace `panic = warn`,
///   `unwrap_used = deny`).
/// - No use-after-free / out-of-bounds (libxml2 wrapper safety).
/// - No unbounded allocation (input length is the only growth bound).
///
/// `cargo fuzz run saml_assertion -- -max_total_time=60` exercises
/// the smoke window; the full corpus is documented in
/// `fuzz/corpus/saml_assertion/README.md` (deferred follow-up).
#[doc(hidden)]
pub fn fuzz_entry(bytes: &[u8]) {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;

    // Path 1: bytes-as-base64-XML.
    if let Ok(decoded) = BASE64_STANDARD.decode(bytes)
        && let Ok(xml) = std::str::from_utf8(&decoded)
    {
        run_fuzz_pipeline(xml);
    }

    // Path 2: bytes-as-raw-XML.
    if let Ok(xml) = std::str::from_utf8(bytes) {
        run_fuzz_pipeline(xml);
    }
}

fn run_fuzz_pipeline(xml: &str) {
    // Whole-document DTD/ENTITY reject — pure-Rust string ops, no
    // allocation hazard.
    let _ = reject_dtd_or_external_entity(xml);

    let sp = ServiceProvider {
        entity_id: Some("https://fuzz.zagrosi/sp".to_owned()),
        acs_url: Some("https://fuzz.zagrosi/sp/acs".to_owned()),
        slo_url: None,
        // Empty `idp_metadata` → `idp_signing_certs()` returns None,
        // and `reduce_xml_to_signed` skips signature verification
        // entirely (samael line 399-401). The fuzz path therefore
        // exercises the libxml2 / xmlsec XML decode + reducer
        // surface without depending on a signed corpus.
        idp_metadata: EntityDescriptor::default(),
        allow_idp_initiated: false,
        ..ServiceProvider::default()
    };
    let possible_request_ids: [&str; 1] = ["fuzz-req-id"];
    // Pin `ReduceMode::ValidateAndMarkNoAncestors` so the fuzz
    // surface mirrors the prod handler's reduction posture verbatim.
    // Calling the unpinned `parse_xml_response` would let a future
    // samael default flip silently weaken the fuzz coverage relative
    // to prod.
    let _ = sp.parse_xml_response_with_mode(
        xml,
        Some(&possible_request_ids[..]),
        ReduceMode::ValidateAndMarkNoAncestors,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic but base64-valid body (32 'A' chars decode to 24
    // null bytes). Exact bytes don't matter for the body-extract
    // tests; what matters is that the round-trip base64 sanity
    // check inside `pem_certificate_body` accepts the value.
    const SAMPLE_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAAAAAAAAAA\nAAAAAAAA\n-----END CERTIFICATE-----\n";

    #[test]
    fn pem_body_strips_markers_and_whitespace() {
        let body = pem_certificate_body(SAMPLE_PEM).expect("body");
        assert_eq!(body, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn pem_body_rejects_missing_markers() {
        let err = pem_certificate_body("not a pem").expect_err("rejected");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    #[test]
    fn dtd_rejected_at_pre_flight() {
        let xml = "<?xml version=\"1.0\"?>\n<!DOCTYPE foo [<!ENTITY xxe \"bar\">]>\n<Response/>";
        let err = reject_dtd_or_external_entity(xml).expect_err("rejected");
        assert_eq!(err.sub_reason(), "dtd_rejected");
    }

    #[test]
    fn external_entity_rejected_at_pre_flight() {
        let xml =
            "<?xml version=\"1.0\"?>\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n<Response/>";
        let err = reject_dtd_or_external_entity(xml).expect_err("rejected");
        assert_eq!(err.sub_reason(), "external_entity_rejected");
    }

    #[test]
    fn pre_flight_passes_clean_payload() {
        let xml = "<?xml version=\"1.0\"?><saml:Response xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"/>";
        reject_dtd_or_external_entity(xml).expect("clean payload accepted");
    }

    /// Regression: a 4096-byte string whose 4096th byte landed
    /// mid-codepoint used to panic at `&xml[..head_end]`.
    /// `reject_dtd_or_external_entity` now scans the whole document
    /// without slicing, so multi-byte codepoints anywhere in the
    /// payload are safe.
    #[test]
    fn pre_flight_handles_multibyte_codepoint_at_4kib_boundary() {
        // Build a string that places a 4-byte UTF-8 codepoint
        // straddling byte index 4096 — the prior bound's slice
        // boundary. Filler is plain ASCII to make byte length
        // predictable.
        let filler_len = 4093;
        let mut xml = String::with_capacity(filler_len + 8);
        xml.push_str(&"a".repeat(filler_len));
        xml.push('𝄞'); // U+1D11E, encodes to 4 UTF-8 bytes (F0 9D 84 9E)
        xml.push_str("<x/>");
        // Sanity: the 4-byte codepoint straddles byte index 4096.
        assert!(xml.len() > 4096);
        // Function must NOT panic.
        let result = reject_dtd_or_external_entity(&xml);
        result.expect("clean multi-byte payload accepted");
    }

    /// Regression: a malicious payload with the DOCTYPE pushed past
    /// the prior 4 KiB head bound (e.g. behind a giant XML comment
    /// prologue) no longer slips through. The whole-document scan
    /// catches DOCTYPE wherever it appears.
    #[test]
    fn pre_flight_rejects_dtd_past_4kib_boundary() {
        let mut xml = String::from("<?xml version=\"1.0\"?>");
        xml.push_str("<!--");
        xml.push_str(&"x".repeat(8192));
        xml.push_str("-->\n<!DOCTYPE foo [<!ENTITY xxe \"bar\">]>\n<Response/>");
        let err = reject_dtd_or_external_entity(&xml).expect_err("must reject");
        assert_eq!(err.sub_reason(), "dtd_rejected");
    }

    #[test]
    fn pem_body_rejects_multi_cert_bundle() {
        let bundle = "-----BEGIN CERTIFICATE-----\nAAA=\n-----END CERTIFICATE-----\n\
                      -----BEGIN CERTIFICATE-----\nBBB=\n-----END CERTIFICATE-----\n";
        let err = pem_certificate_body(bundle).expect_err("bundle rejected");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    /// Build a minimal `Assertion` fixture with caller-supplied
    /// subject + conditions. Every other field defaults to None /
    /// empty so the fixture isolates the field under test. Reduces
    /// the per-test struct-literal boilerplate from ~13 lines to a
    /// single call.
    fn fixture_assertion(
        subject: Option<samael::schema::Subject>,
        conditions: Option<samael::schema::Conditions>,
    ) -> Assertion {
        Assertion {
            id: "id-test".into(),
            issue_instant: chrono::Utc::now(),
            version: "2.0".into(),
            issuer: samael::schema::Issuer::default(),
            signature: None,
            subject,
            conditions,
            authn_statements: None,
            attribute_statements: None,
        }
    }

    /// Build a minimal `Subject` containing a single `NameID` with
    /// the supplied `format` + `value`.
    fn fixture_subject(format: Option<&str>, value: &str) -> samael::schema::Subject {
        samael::schema::Subject {
            name_id: Some(samael::schema::SubjectNameID {
                format: format.map(str::to_owned),
                value: value.to_owned(),
            }),
            subject_confirmations: None,
        }
    }

    /// Build a minimal `Conditions` with caller-supplied
    /// `audience_restrictions`. Every other field is `None`.
    fn fixture_conditions(
        audience_restrictions: Option<Vec<samael::schema::AudienceRestriction>>,
    ) -> samael::schema::Conditions {
        samael::schema::Conditions {
            not_before: None,
            not_on_or_after: None,
            audience_restrictions,
            one_time_use: None,
            proxy_restriction: None,
        }
    }

    #[test]
    fn nameid_value_rejects_transient_v2_format() {
        let assertion = fixture_assertion(
            Some(fixture_subject(
                Some(NAMEID_FORMAT_TRANSIENT_V2),
                "transient-12345",
            )),
            None,
        );
        let err = nameid_value(&assertion).expect_err("transient rejected");
        assert_eq!(err.sub_reason(), "subject_confirmation_invalid");
    }

    #[test]
    fn nameid_value_rejects_transient_v1_format() {
        let assertion = fixture_assertion(
            Some(fixture_subject(
                Some(NAMEID_FORMAT_TRANSIENT_V1),
                "transient-12345",
            )),
            None,
        );
        let err = nameid_value(&assertion).expect_err("transient rejected");
        assert_eq!(err.sub_reason(), "subject_confirmation_invalid");
    }

    #[test]
    fn nameid_value_accepts_persistent_format() {
        let assertion = fixture_assertion(
            Some(fixture_subject(
                Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
                "alice@idp",
            )),
            None,
        );
        let value = nameid_value(&assertion).expect("persistent accepted");
        assert_eq!(value, "alice@idp");
    }

    #[test]
    fn require_conditions_rejects_assertion_without_conditions() {
        let assertion = fixture_assertion(None, None);
        let err = require_conditions_and_audience(&assertion).expect_err("rejected");
        assert_eq!(err.sub_reason(), "conditions_window_invalid");
    }

    #[test]
    fn require_conditions_rejects_conditions_without_audience() {
        let assertion = fixture_assertion(None, Some(fixture_conditions(None)));
        let err = require_conditions_and_audience(&assertion).expect_err("rejected");
        assert_eq!(err.sub_reason(), "audience_mismatch");
    }

    /// Defence-in-depth: an `AudienceRestriction` with a populated
    /// list-of-restrictions but an empty inner audience Vec slips
    /// past samael's `iter().any(...)` content check (which returns
    /// false on empty AND drops through to a uniform reject — but
    /// the surface depends on samael internals). Pin the explicit
    /// non-empty inner list invariant in our handler.
    #[test]
    fn require_conditions_rejects_audience_restriction_with_empty_inner_list() {
        let assertion = fixture_assertion(
            None,
            Some(fixture_conditions(Some(vec![
                samael::schema::AudienceRestriction { audience: vec![] },
            ]))),
        );
        let err = require_conditions_and_audience(&assertion).expect_err("rejected");
        assert_eq!(err.sub_reason(), "audience_mismatch");
    }

    #[test]
    fn nameid_value_rejects_missing_format_attribute() {
        let assertion = fixture_assertion(Some(fixture_subject(None, "alice@idp")), None);
        let err = nameid_value(&assertion).expect_err("missing format rejected");
        assert_eq!(err.sub_reason(), "subject_confirmation_invalid");
    }

    #[test]
    fn pem_body_rejects_typed_pem_block() {
        let typed = "-----BEGIN TRUSTED CERTIFICATE-----\n\
                     MIIDazCCAlOgAwIBAgIUO\nABCDEF==\n\
                     -----END TRUSTED CERTIFICATE-----\n";
        let err = pem_certificate_body(typed).expect_err("typed PEM rejected");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    #[test]
    fn pem_body_rejects_private_key_pem() {
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   MIIBVgIBADANBg==\n\
                   -----END PRIVATE KEY-----\n";
        let err = pem_certificate_body(pem).expect_err("private key PEM rejected");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    #[test]
    fn pem_body_rejects_non_base64_body() {
        let pem = "-----BEGIN CERTIFICATE-----\n\
                   not!valid base64@@@\n\
                   -----END CERTIFICATE-----\n";
        let err = pem_certificate_body(pem).expect_err("non-base64 body rejected");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    /// Regression: ENTITY-past-4 KiB boundary. Parallel coverage to
    /// `pre_flight_rejects_dtd_past_4kib_boundary`. The whole-doc
    /// scan must catch ENTITY declarations regardless of where they
    /// appear in the payload.
    #[test]
    fn pre_flight_rejects_external_entity_past_4kib_boundary() {
        let mut xml = String::from("<?xml version=\"1.0\"?>");
        xml.push_str("<!--");
        xml.push_str(&"x".repeat(8192));
        xml.push_str("-->\n<!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n<Response/>");
        let err = reject_dtd_or_external_entity(&xml).expect_err("must reject");
        assert_eq!(err.sub_reason(), "external_entity_rejected");
    }
}
