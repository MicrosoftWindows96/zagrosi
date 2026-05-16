// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SP metadata endpoint + first-call signing-key generation.
//!
//! Section-11 spec lines 184-197 enumerate the contract:
//!
//! 1. First request for an org with no `sp_signing_key` →
//!    generate a fresh keypair + self-signed X.509 cert, envelope-
//!    encrypt the private key via `crypto::Secrets` (section-04 shim),
//!    UPDATE `org_idps.config` with the envelope + cert PEM.
//! 2. Build an `EntityDescriptor` containing the SP's
//!    `SPSSODescriptor` with one `KeyDescriptor` (signing) carrying
//!    the public cert (`X509Certificate` element) and the
//!    `AssertionConsumerService` (HTTP-POST binding) pointing at the
//!    org's ACS URL.
//! 3. Serialise via samael's `ToXml` impl. v0.1 returns the metadata
//!    document unsigned — admins that require signed metadata wire
//!    it through their CDN's signing layer or run the optional
//!    `Crypto::sign_xml` step (deferred follow-up: per-org admin
//!    toggle for metadata signing).
//!
//! Subsequent requests load + return idempotently.
//!
//! ## Concurrency on first call
//!
//! Two requests racing the very first metadata fetch each generate a
//! distinct keypair + cert. Both succeed; last writer wins on the
//! `org_idps.config` UPDATE. The downstream IdP fetches the metadata
//! document once and caches the cert; the cert published always
//! matches what is currently persisted. SP key rotation is admin-
//! triggered (deferred follow-up); v0.1 treats the first-write race
//! as benign.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use samael::crypto::CertificateDer;
use samael::idp::{Elliptic, IdentityProvider, KeyType, Rsa};
use samael::key_info::{KeyInfo, X509Data};
use samael::metadata::{
    EntityDescriptor, HTTP_POST_BINDING, IndexedEndpoint, KeyDescriptor, SpSsoDescriptor,
};
use samael::traits::ToXml;
use zeroize::Zeroizing;

use crate::crypto::Secrets;
use crate::crypto::secrets::Envelope;
use crate::error::IdentityError;
use crate::repo::{OrgIdpRepo, OrgRepo, OrgScoped};

use super::authn;
use super::config::{EncryptedKey, SamlConfigV1, SpSigningAlg};
use super::errors::SamlError;

/// Default validity duration for the SP signing certificate (10
/// years). The cert is self-signed and re-issued only when the admin
/// triggers rotation; the lifetime mirrors industry-standard SAML SP
/// deployments where IdPs cache the metadata document with weekly
/// refresh.
pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 3652;

/// Metadata document validity advertised in the
/// `EntityDescriptor/@validUntil` attribute. Tells consuming IdPs
/// when they should re-fetch the metadata XML.
pub const DEFAULT_METADATA_VALIDITY_HOURS: i64 = 48;

/// Composed dependency bundle for [`handler`].
#[derive(Clone)]
pub struct MetadataDeps {
    /// Org lookup (slug → row).
    pub orgs: OrgRepo,
    /// IdP lookup + config update path.
    pub idps: OrgIdpRepo,
    /// Section-04 secrets shim.
    pub secrets: Arc<Secrets>,
    /// Public base URL.
    pub base_url: Arc<str>,
}

/// SP metadata response payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MetadataResponse {
    /// `EntityDescriptor` XML (UTF-8).
    pub xml: String,
    /// Whether the metadata document carries a `<ds:Signature>`.
    pub signed: bool,
}

/// Run the metadata endpoint.
///
/// # Errors
///
/// - [`SamlError::OrgNotFound`] when the slug does not resolve.
/// - [`SamlError::IdpNotFound`] when no enabled SAML IdP exists.
/// - [`SamlError::ConfigInvalid`] when stored config fails revalidation.
/// - [`SamlError::MetadataKeyProvisioningFailed`] when the first-call
///   key-generation, envelope-encrypt, or persist path errors.
#[tracing::instrument(
    skip_all,
    fields(
        org_slug = %org_slug,
        route = "saml.metadata",
    )
)]
pub async fn handler(deps: &MetadataDeps, org_slug: &str) -> Result<MetadataResponse, SamlError> {
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
        .filter(|idp| idp.enabled && idp.protocol == "saml")
        .collect();
    if saml_idps.is_empty() {
        return Err(SamlError::IdpNotFound);
    }
    if saml_idps.len() > 1 {
        return Err(SamlError::AmbiguousIdp);
    }
    let idp = saml_idps.remove(0);
    let mut cfg = SamlConfigV1::from_jsonb(&idp.config)?;

    // Defence-in-depth slug validation. The slug flows into the
    // self-signed cert's CommonName via `provision_sp_signing_material`;
    // an admin layer that ever lets a slug carry RDN-active
    // characters (`,` `+` `=` `"` `\` `<` `>` `;` NUL) would let an
    // operator inject extra RDN components. Validate before keygen.
    validate_org_slug_for_cert(org_slug)?;

    let cert_pem = match (&cfg.sp_signing_key, &cfg.sp_signing_cert_pem) {
        (Some(envelope), Some(pem)) => {
            // Sanity-check the persisted (envelope, cert) pair. The
            // existing CAS UPDATE writes BOTH fields atomically so
            // a partial-state row is unreachable through the normal
            // path; this guard catches the residual cases:
            //
            //   1. Admin manually edited `org_idps.config` JSONB
            //      and inserted one field without the other.
            //   2. KEK rotated since the envelope was sealed (the
            //      decrypt fails fast — UnknownKeyId / IntegrityError).
            //   3. The cert PEM body got corrupted in transit
            //      (catches base64-corrupt body via
            //      `pem_certificate_body`'s round-trip check, used
            //      downstream when we serialise metadata).
            //
            // We do NOT semantically verify cert↔key linkage (i.e.
            // confirm the cert's public key matches the envelope's
            // private key). That requires a full X.509 + DER parse
            // pass and is a deferred follow-up; the practical
            // failure mode is admin manual edit, which the simple
            // decrypt-and-validate-PEM check already covers.
            verify_persisted_signing_material(&deps.secrets, envelope, pem)?;
            pem.clone()
        }
        _ => {
            // First call (or partially-provisioned config): mint a
            // fresh keypair + cert and persist via the optimistic-
            // concurrency CAS path. Two writers racing the very
            // first metadata fetch each generate a distinct keypair;
            // only one CAS succeeds (`config_version` matches), the
            // other re-loads the persisted config and returns the
            // winner's cert verbatim — IdPs that fetch metadata
            // never see the loser's cert.
            persist_first_call_or_reload(
                deps,
                org_slug,
                &authn::derive_entity_id(&deps.base_url),
                idp.id,
                &mut cfg,
                idp.config_version,
                org.id,
            )
            .await?
        }
    };

    let xml = build_entity_descriptor_xml(&deps.base_url, org_slug, &cert_pem)?;
    Ok(MetadataResponse { xml, signed: false })
}

/// Generated SP signing material. The envelope wraps the private key
/// (PKCS#8 DER) under the section-04 secrets shim; the cert PEM is
/// the public companion published in metadata.
struct ProvisionedKey {
    envelope: Envelope,
    cert_pem: String,
}

/// First-call key generation. Generates a keypair via samael's
/// openssl-backed [`IdentityProvider`] (which is correctly named for
/// IdP test fixtures but is also the right primitive for SP keygen
/// here — it issues a self-signed X.509 over the private key, which
/// is what an SP entity needs for the `<X509Certificate>` element in
/// metadata + for xmlsec-driven metadata signing). The keypair lives
/// only in this function; the private DER bytes go straight into the
/// AES-256-GCM envelope and the cert DER is base64-PEM-wrapped for
/// the public metadata document.
fn provision_sp_signing_material(
    secrets: &Arc<Secrets>,
    alg: SpSigningAlg,
    org_slug: &str,
    entity_id: &str,
) -> Result<ProvisionedKey, SamlError> {
    let key_type = match alg {
        SpSigningAlg::Rsa2048 => KeyType::Rsa(Rsa::Rsa2048),
        SpSigningAlg::P256 => KeyType::Elliptic(Elliptic::NISTP256),
    };
    let provider = IdentityProvider::generate_new(key_type).map_err(|err| {
        tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp keygen failed");
        SamlError::MetadataKeyProvisioningFailed
    })?;

    let common_name = format!("zagrosi-saml-sp:{org_slug}");
    let cert_der: CertificateDer = provider
        .create_certificate(&samael::idp::CertificateParams {
            common_name: &common_name,
            issuer_name: entity_id,
            days_until_expiration: DEFAULT_CERT_VALIDITY_DAYS,
        })
        .map_err(|err| {
            tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp cert issue failed");
            SamlError::MetadataKeyProvisioningFailed
        })?;

    // Wrap the private DER bytes in `Zeroizing` so the heap buffer
    // is scrubbed on drop. `secrets.seal` borrows; the wrapper keeps
    // the plaintext bytes off the long-tail heap state once seal
    // returns.
    let private_key_der: Zeroizing<Vec<u8>> =
        Zeroizing::new(provider.export_private_key_der().map_err(|err| {
            tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp private key export failed");
            SamlError::MetadataKeyProvisioningFailed
        })?);

    let envelope = secrets.seal(&private_key_der).map_err(|err| {
        tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp private key seal failed");
        SamlError::MetadataKeyProvisioningFailed
    })?;

    let cert_pem = der_to_pem(cert_der.der_data());
    Ok(ProvisionedKey { envelope, cert_pem })
}

/// Sanity-check that the persisted SP signing envelope decrypts
/// under the live KEK and that the persisted cert PEM is
/// well-formed (markers + base64 body). Returns
/// [`SamlError::MetadataKeyProvisioningFailed`] when the envelope
/// fails to decrypt (KEK rotated without admin re-wrap; admin
/// manual JSONB edit) OR the cert PEM is corrupt. The plaintext
/// private key bytes drop on the spot — they are not returned.
fn verify_persisted_signing_material(
    secrets: &Arc<Secrets>,
    encrypted_key: &EncryptedKey,
    cert_pem: &str,
) -> Result<(), SamlError> {
    let envelope: Envelope = encrypted_key.into();
    let private_key_der: Zeroizing<Vec<u8>> = match secrets.open(&envelope) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) => {
            tracing::warn!(
                target: "zagrosi.identity.saml",
                error = %err,
                "saml metadata: persisted sp_signing_key envelope decrypt failed (KEK mismatch or corrupt)"
            );
            return Err(SamlError::MetadataKeyProvisioningFailed);
        }
    };
    if private_key_der.is_empty() {
        return Err(SamlError::MetadataKeyProvisioningFailed);
    }
    // `pem_certificate_body` round-trips the PEM body through the
    // strict marker + base64 sanity guards introduced in the
    // round-2 hardening commit. A corrupt cert PEM surfaces here
    // rather than at the IdP fetch downstream.
    pem_certificate_body(cert_pem)?;
    Ok(())
}

/// First-call SP signing-key persist with optimistic-concurrency
/// retry. Generates a fresh keypair + cert, attempts the CAS
/// `update_config(.., expected_version)`, and on conflict re-loads
/// the now-persisted state and returns the winner's cert. The
/// freshly-minted (loser) keypair drops + zeroes out without ever
/// reaching the persist path.
async fn persist_first_call_or_reload(
    deps: &MetadataDeps,
    org_slug: &str,
    entity_id: &str,
    org_idp_id: uuid::Uuid,
    cfg: &mut SamlConfigV1,
    expected_version: i16,
    org_id: uuid::Uuid,
) -> Result<String, SamlError> {
    let provisioned =
        provision_sp_signing_material(&deps.secrets, cfg.sp_signing_alg, org_slug, entity_id)?;

    cfg.sp_signing_key = Some(provisioned.envelope.into());
    cfg.sp_signing_cert_pem = Some(provisioned.cert_pem.clone());

    let new_config = serde_json::to_value(&*cfg).map_err(|err| {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            error = %err,
            "saml metadata: serialise updated config"
        );
        SamlError::MetadataKeyProvisioningFailed
    })?;

    let scoped = OrgScoped::new(&deps.idps, org_id);
    match scoped
        .update_config(org_idp_id, new_config, expected_version)
        .await
    {
        Ok(_) => {
            // We won the CAS — emit a high-signal audit event for
            // the rare admin-grade "SP key minted" milestone. The
            // zagrosi-audit Auditor port is not wired into the
            // metadata service yet (deferred follow-up); the
            // structured tracing field carries the same
            // information for the SIEM-side ingestion pipeline.
            //
            // The fingerprint is built via `cert_fingerprint_sha256_b64`
            // which propagates parse failures rather than silently
            // emitting a SHA-256 of an empty buffer (the prior
            // `unwrap_or_default()` chain produced a constant
            // `e3b0c44...` digest on malformed PEM, poisoning the
            // audit dashboard with a plausible-looking-but-wrong
            // fingerprint). On a successful provisioning the cert
            // we just minted is by construction well-formed, so
            // the propagation here is a defensive guard rather
            // than a reachable error path.
            let cert_fp_b64 = cert_fingerprint_sha256_b64(&provisioned.cert_pem)?;
            tracing::info!(
                target: "zagrosi.identity.saml",
                audit = "saml_sp_key_provisioned",
                org_id = %org_id,
                org_idp_id = %org_idp_id,
                alg = ?cfg.sp_signing_alg,
                cert_sha256_b64 = %cert_fp_b64,
                "SAML SP signing key provisioned for org"
            );
            Ok(provisioned.cert_pem)
        }
        Err(IdentityError::OptimisticLockConflict) => {
            // Lost the race. Re-load the persisted IdP row and
            // return the winner's cert. The freshly-minted private
            // key never reaches the DB; it drops here and the
            // Zeroizing wrapper inside `provision_sp_signing_material`
            // already scrubbed the plaintext DER bytes.
            tracing::info!(
                target: "zagrosi.identity.saml",
                audit = "saml_sp_key_provisioning_race_lost",
                org_id = %org_id,
                org_idp_id = %org_idp_id,
                "concurrent first-call beat us; using persisted cert"
            );
            let live = scoped
                .find_by_id(org_idp_id)
                .await
                .map_err(|err| {
                    tracing::warn!(
                        target: "zagrosi.identity.saml",
                        error = %err,
                        "saml metadata: re-load after CAS conflict failed"
                    );
                    SamlError::MetadataKeyProvisioningFailed
                })?
                .ok_or(SamlError::IdpNotFound)?;

            // Re-run the gating that the handler ran on the initial
            // read. Between our read and the conflict-resolving
            // re-read, an admin could have soft-deleted, disabled,
            // or flipped the protocol on the row. Without this
            // guard, the metadata response would happily serve a
            // cert from a now-disabled IdP — silently bypassing
            // the admin's kill-switch.
            if !live.enabled || live.protocol != "saml" {
                tracing::warn!(
                    target: "zagrosi.identity.saml",
                    org_id = %org_id,
                    org_idp_id = %org_idp_id,
                    enabled = %live.enabled,
                    protocol = %live.protocol,
                    "saml metadata: race-lost reload found IdP no longer eligible"
                );
                return Err(SamlError::IdpNotFound);
            }

            let live_cfg = SamlConfigV1::from_jsonb(&live.config)?;
            live_cfg
                .sp_signing_cert_pem
                .ok_or(SamlError::MetadataKeyProvisioningFailed)
        }
        Err(err) => {
            tracing::warn!(
                target: "zagrosi.identity.saml",
                error = %err,
                "saml metadata: persist sp_signing_key envelope"
            );
            Err(SamlError::MetadataKeyProvisioningFailed)
        }
    }
}

/// Compute the SHA-256 fingerprint of the cert PEM body, returned
/// as a base64-encoded string. Surfaces parse failures rather than
/// silently emitting a SHA-256 of an empty buffer (the prior
/// `unwrap_or_default()` chain produced a constant `e3b0c44...`
/// digest on malformed PEM, which would have poisoned the audit
/// dashboard with a plausible-looking fingerprint).
fn cert_fingerprint_sha256_b64(cert_pem: &str) -> Result<String, SamlError> {
    use sha2::{Digest, Sha256};
    let body = pem_certificate_body(cert_pem)?;
    let der = base64::Engine::decode(&BASE64_STANDARD, body).map_err(|err| {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            error = %err,
            "saml metadata: cert fingerprint base64 decode failed"
        );
        SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem fingerprint: body is not valid base64".to_owned(),
        }
    })?;
    let digest = Sha256::digest(&der);
    Ok(BASE64_STANDARD.encode(digest))
}

/// Reject org slugs that carry RDN-active characters or NUL bytes.
/// The slug feeds `samael::idp::CertificateParams::common_name`
/// (which forwards to openssl's `X509_NAME_add_entry_by_txt`); a
/// slug containing `,` `+` `=` `"` `\` `<` `>` `;` or NUL would
/// inject extra RDN components or terminate the X.500 string early.
/// The admin layer SHOULD validate slug shape at write time; this
/// is defence-in-depth.
fn validate_org_slug_for_cert(org_slug: &str) -> Result<(), SamlError> {
    if org_slug.is_empty() || org_slug.len() > 63 {
        return Err(SamlError::ConfigInvalid {
            reason: "org_slug length out of bounds for X.509 CommonName".to_owned(),
        });
    }
    for ch in org_slug.chars() {
        let ok = ch.is_ascii_alphanumeric() || ch == '-' || ch == '_';
        if !ok {
            return Err(SamlError::ConfigInvalid {
                reason: format!("org_slug contains character `{ch}` not safe for X.509 CommonName",),
            });
        }
    }
    Ok(())
}

/// Render a DER-encoded X.509 certificate as a PEM-formatted string.
/// 64-char base64 lines per RFC 7468 §3.
fn der_to_pem(der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + 64);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

/// Strip PEM markers and return the base64 body with whitespace
/// removed. Mirrors [`super::acs::pem_certificate_body`] (kept as a
/// local copy so the metadata module is loadable without the ACS
/// module). The two copies share the round-2 hardening guards:
/// EXACT PEM-type match (CERTIFICATE only — `BEGIN TRUSTED CERTIFICATE`,
/// `BEGIN PRIVATE KEY` reject), single-cert (chain bundles reject),
/// and base64 round-trip (corrupt body rejects fast). A future
/// dedup pass moves this into a shared `saml::cert` module.
fn pem_certificate_body(pem: &str) -> Result<String, SamlError> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    for match_idx in pem.match_indices("-----BEGIN ").map(|(idx, _)| idx) {
        let after_prefix = &pem[match_idx + "-----BEGIN ".len()..];
        let Some(dashes) = after_prefix.find("-----") else {
            return Err(SamlError::ConfigInvalid {
                reason: "sp_signing_cert_pem BEGIN line lacks closing dashes".to_owned(),
            });
        };
        let pem_type = &after_prefix[..dashes];
        if pem_type != "CERTIFICATE" {
            return Err(SamlError::ConfigInvalid {
                reason: format!(
                    "sp_signing_cert_pem must contain a CERTIFICATE PEM block, found `{pem_type}`"
                ),
            });
        }
    }

    let begin = pem.find(BEGIN);
    let end = pem.find(END);
    let (Some(b), Some(e)) = (begin, end) else {
        return Err(SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem missing markers".to_owned(),
        });
    };
    if e <= b {
        return Err(SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem markers in wrong order".to_owned(),
        });
    }

    let after_first = &pem[e + END.len()..];
    if after_first.contains(BEGIN) {
        return Err(SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem must contain exactly one certificate".to_owned(),
        });
    }

    let body = &pem[b + BEGIN.len()..e];
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem body empty".to_owned(),
        });
    }
    if base64::Engine::decode(&BASE64_STANDARD, &cleaned).is_err() {
        return Err(SamlError::ConfigInvalid {
            reason: "sp_signing_cert_pem body is not valid base64".to_owned(),
        });
    }
    Ok(cleaned)
}

/// Build the SP `EntityDescriptor` XML document. Done by hand (rather
/// than via [`samael::service_provider::ServiceProvider::metadata`])
/// to avoid samael's hard requirement on a populated SLO URL — SLO is
/// out of scope for v0.1 (section-11 spec line 339).
fn build_entity_descriptor_xml(
    base_url: &str,
    org_slug: &str,
    cert_pem: &str,
) -> Result<String, SamlError> {
    let cert_b64 = pem_certificate_body(cert_pem)?;
    let acs_url = authn::derive_acs_url(base_url, org_slug);
    let entity_id = authn::derive_entity_id(base_url);

    let valid_until = chrono::Utc::now() + chrono::Duration::hours(DEFAULT_METADATA_VALIDITY_HOURS);

    let key_descriptor = KeyDescriptor {
        key_use: Some("signing".to_owned()),
        key_info: KeyInfo {
            id: None,
            x509_data: Some(X509Data {
                certificates: vec![cert_b64],
            }),
        },
        encryption_methods: None,
    };

    let sp_descriptor = SpSsoDescriptor {
        protocol_support_enumeration: Some("urn:oasis:names:tc:SAML:2.0:protocol".to_owned()),
        key_descriptors: Some(vec![key_descriptor]),
        valid_until: Some(valid_until),
        single_logout_services: None,
        authn_requests_signed: Some(false),
        want_assertions_signed: Some(true),
        assertion_consumer_services: vec![IndexedEndpoint {
            binding: HTTP_POST_BINDING.to_owned(),
            location: acs_url,
            response_location: None,
            index: 0,
            is_default: Some(true),
        }],
        ..SpSsoDescriptor::default()
    };

    let entity_descriptor = EntityDescriptor {
        entity_id: Some(entity_id),
        valid_until: Some(valid_until),
        sp_sso_descriptors: Some(vec![sp_descriptor]),
        ..EntityDescriptor::default()
    };

    entity_descriptor.to_string().map_err(|err| {
        tracing::warn!(
            target: "zagrosi.identity.saml",
            error = %err,
            "metadata serialise failed"
        );
        SamlError::MetadataKeyProvisioningFailed
    })
}

/// Test-only: generate a fresh SP signing keypair and return raw
/// PKCS#1 / sec1 DER private key bytes. Production paths MUST use
/// [`provision_sp_signing_material`] which envelope-encrypts the
/// private DER via the section-04 secrets shim before returning.
/// Keeping this entry-point under `#[cfg(test)]` removes the
/// dead-pub footgun where a production caller could exfiltrate
/// raw key material with no auth + no audit.
#[cfg(test)]
fn generate_sp_signing_key(alg: SpSigningAlg) -> Result<Vec<u8>, SamlError> {
    let key_type = match alg {
        SpSigningAlg::Rsa2048 => KeyType::Rsa(Rsa::Rsa2048),
        SpSigningAlg::P256 => KeyType::Elliptic(Elliptic::NISTP256),
    };
    let provider = IdentityProvider::generate_new(key_type).map_err(|err| {
        tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp keygen failed");
        SamlError::MetadataKeyProvisioningFailed
    })?;
    provider.export_private_key_der().map_err(|err| {
        tracing::warn!(target: "zagrosi.identity.saml", error = %err, "sp private key export failed");
        SamlError::MetadataKeyProvisioningFailed
    })
}

/// Derive the SP entity id (mirrors [`super::authn::derive_entity_id`]).
#[must_use]
pub fn derive_entity_id(base_url: &str) -> String {
    authn::derive_entity_id(base_url)
}

/// Map a repo-layer [`IdentityError`] onto the SAML error surface.
fn repo_error(err: &IdentityError) -> SamlError {
    tracing::warn!(target: "zagrosi.identity.saml", error = %err, "saml metadata: repo error");
    SamlError::Internal
}

impl From<Envelope> for EncryptedKey {
    fn from(env: Envelope) -> Self {
        Self {
            key_id: env.key_id,
            nonce: env.nonce,
            ciphertext: env.ciphertext,
            tag: env.tag,
        }
    }
}

impl From<&EncryptedKey> for Envelope {
    fn from(key: &EncryptedKey) -> Self {
        Self {
            key_id: key.key_id.clone(),
            nonce: key.nonce.clone(),
            ciphertext: key.ciphertext.clone(),
            tag: key.tag.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_to_pem_round_trips() {
        let der = b"\x30\x82\x01\x00fake-der-bytes";
        let pem = der_to_pem(der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let body = pem_certificate_body(&pem).expect("body");
        let decoded = BASE64_STANDARD.decode(&body).expect("decode");
        assert_eq!(decoded, der);
    }

    #[test]
    fn rsa2048_keygen_returns_pkcs8_blob() {
        let blob = generate_sp_signing_key(SpSigningAlg::Rsa2048).expect("keygen");
        assert!(blob.len() > 900, "blob too small: {}", blob.len());
        // PKCS#1 / PKCS#8 / sec1 all start with `0x30` (SEQUENCE).
        assert_eq!(blob[0], 0x30, "DER must start with SEQUENCE tag");
    }

    #[test]
    fn p256_keygen_returns_short_der_blob() {
        let blob = generate_sp_signing_key(SpSigningAlg::P256).expect("keygen");
        // EC P-256 sec1 DER is in the 100-200 byte range.
        assert!(
            blob.len() > 50 && blob.len() < 300,
            "blob len: {}",
            blob.len()
        );
        assert_eq!(blob[0], 0x30, "DER must start with SEQUENCE tag");
    }
}
