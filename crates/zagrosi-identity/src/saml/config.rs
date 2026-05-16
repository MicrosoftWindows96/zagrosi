// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Versioned SAML config (`org_idps.config` JSONB).
//!
//! Mirrors the contract of [`crate::oidc::config::OidcConfigV1`]: the
//! admin-write path serialises this struct, the SP re-validates on
//! every callback. `config_version = 1` is the only currently-defined
//! shape; section-13 introduces v2 with multi-IdP routing.

use serde::{Deserialize, Serialize};

/// SP signing-key algorithm. RSA-2048 is the default; P-256 is opt-in
/// for orgs whose IdPs negotiate ECDSA. Both are supported by samael's
/// xmlsec backend and by the workspace `aws-lc-rs` crypto provider
/// used at key-gen time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpSigningAlg {
    /// RSA-2048 with SHA-256 (RSASSA-PKCS1-v1_5). Default.
    #[default]
    Rsa2048,
    /// ECDSA P-256 with SHA-256.
    P256,
}

/// Default-mapping field selectors. The values default to widely-used
/// SAML attribute names (`mail`, `givenName`, `sn`); admins override
/// per-IdP for non-conformant deployments. Empty-string values disable
/// the mapping (e.g. an IdP that never emits `groups`).
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct AttributeMapping {
    /// Attribute carrying the user's email (default `mail`).
    #[serde(default = "default_email_attr")]
    pub email: String,
    /// Attribute carrying the user's given name (default `givenName`).
    #[serde(default = "default_given_name_attr")]
    pub given_name: String,
    /// Attribute carrying the user's family name (default `sn`).
    #[serde(default = "default_family_name_attr")]
    pub family_name: String,
    /// Attribute carrying group memberships. `None` disables groups.
    #[serde(default)]
    pub groups: Option<String>,
}

fn default_email_attr() -> String {
    "mail".to_owned()
}

fn default_given_name_attr() -> String {
    "givenName".to_owned()
}

fn default_family_name_attr() -> String {
    "sn".to_owned()
}

impl Default for AttributeMapping {
    /// Field-default mirror so `#[serde(default)]` on `SamlConfigV1`
    /// produces the same shape as if every individual `AttributeMapping`
    /// field had been omitted from the input JSONB.
    fn default() -> Self {
        Self {
            email: default_email_attr(),
            given_name: default_given_name_attr(),
            family_name: default_family_name_attr(),
            groups: None,
        }
    }
}

/// SP signing-key envelope. Mirrors
/// [`crate::oidc::config::EncryptedKey`] structurally so the same
/// section-04 secrets shim seal/open path covers both.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct EncryptedKey {
    /// Section-04 key id (`v0_1` static, future rotation slot).
    pub key_id: String,
    /// 12-byte AES-GCM nonce (base64url).
    pub nonce: String,
    /// Ciphertext (base64url).
    pub ciphertext: String,
    /// 16-byte AES-GCM authentication tag (base64url).
    pub tag: String,
}

/// SAML config v1. Stored as JSONB at `org_idps.config`. The wire
/// shape is stable — admin-write mutations MUST round-trip through
/// the [`Self::validate`] sanity-check before persisting.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SamlConfigV1 {
    /// Schema version. The SP refuses any value other than `1`; the
    /// admin layer migrates rows on deploy.
    pub config_version: u8,
    /// IdP entity id (the canonical SSO anchor `iss` field).
    pub idp_entity_id: String,
    /// IdP SSO URL (HTTP-Redirect or HTTP-POST binding endpoint).
    pub idp_sso_url: String,
    /// PEM-encoded IdP signing certificate. The SP pins this; samael's
    /// `idp_metadata.idp_sso_descriptors[0].key_descriptors` is built
    /// from this PEM at request time.
    pub idp_x509_cert_pem: String,
    /// Whether IdP-initiated SSO is permitted. Default `false` —
    /// login-CSRF mitigation per spec invariant 2.
    #[serde(default)]
    pub allow_idp_initiated: bool,
    /// Whether JIT may bind a new user from the assertion's email
    /// claim. Default `false` per spec invariant 6.
    #[serde(default)]
    pub trust_email_assertion: bool,
    /// Membership role assigned on JIT (default `"member"`).
    #[serde(default = "default_role")]
    pub default_role: String,
    /// Per-IdP attribute mapping overrides.
    #[serde(default)]
    pub attribute_mapping: AttributeMapping,
    /// SP signing-key (envelope-encrypted via section-04 secrets
    /// shim). `None` until the metadata endpoint is hit for the first
    /// time.
    #[serde(default)]
    pub sp_signing_key: Option<EncryptedKey>,
    /// SP signing-key algorithm.
    #[serde(default)]
    pub sp_signing_alg: SpSigningAlg,
    /// SP signing certificate (PEM). The cert is the public companion
    /// to [`Self::sp_signing_key`]; it is published in the SP metadata
    /// document and is therefore stored plaintext. `None` until the
    /// metadata endpoint is hit for the first time.
    #[serde(default)]
    pub sp_signing_cert_pem: Option<String>,
}

fn default_role() -> String {
    "member".to_owned()
}

impl SamlConfigV1 {
    /// Parse from the `org_idps.config` JSONB column. Returns
    /// [`super::SamlError::ConfigInvalid`] on shape mismatch.
    ///
    /// # Errors
    ///
    /// - The JSONB does not deserialise into [`SamlConfigV1`].
    /// - `config_version != 1`.
    pub fn from_jsonb(value: &serde_json::Value) -> Result<Self, super::SamlError> {
        let cfg: Self =
            serde_json::from_value(value.clone()).map_err(|e| super::SamlError::ConfigInvalid {
                reason: format!("deserialise: {e}"),
            })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Sanity-check the parsed config.
    ///
    /// # Errors
    ///
    /// - `config_version != 1`.
    /// - `idp_entity_id` / `idp_sso_url` / `idp_x509_cert_pem` empty.
    /// - PEM does not parse as an X.509 certificate (deferred to the
    ///   SP build path; we only check basic structure here).
    pub fn validate(&self) -> Result<(), super::SamlError> {
        if self.config_version != 1 {
            return Err(super::SamlError::ConfigInvalid {
                reason: format!("unsupported config_version {}", self.config_version),
            });
        }
        if self.idp_entity_id.is_empty() {
            return Err(super::SamlError::ConfigInvalid {
                reason: "idp_entity_id empty".to_owned(),
            });
        }
        if self.idp_sso_url.is_empty() {
            return Err(super::SamlError::ConfigInvalid {
                reason: "idp_sso_url empty".to_owned(),
            });
        }
        if !self.idp_x509_cert_pem.contains("BEGIN CERTIFICATE") {
            return Err(super::SamlError::ConfigInvalid {
                reason: "idp_x509_cert_pem missing PEM header".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_pem() -> &'static str {
        "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let cfg = SamlConfigV1 {
            config_version: 2,
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_x509_cert_pem: ok_pem().into(),
            allow_idp_initiated: false,
            trust_email_assertion: false,
            default_role: "member".into(),
            attribute_mapping: AttributeMapping::default(),
            sp_signing_key: None,
            sp_signing_alg: SpSigningAlg::default(),
            sp_signing_cert_pem: None,
        };
        let err = cfg.validate().expect_err("must reject");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    #[test]
    fn validate_rejects_missing_pem_header() {
        let cfg = SamlConfigV1 {
            config_version: 1,
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_x509_cert_pem: "not a pem".into(),
            allow_idp_initiated: false,
            trust_email_assertion: false,
            default_role: "member".into(),
            attribute_mapping: AttributeMapping::default(),
            sp_signing_key: None,
            sp_signing_alg: SpSigningAlg::default(),
            sp_signing_cert_pem: None,
        };
        let err = cfg.validate().expect_err("must reject");
        assert_eq!(err.sub_reason(), "config_invalid");
    }

    #[test]
    fn happy_path_validates() {
        let cfg = SamlConfigV1 {
            config_version: 1,
            idp_entity_id: "https://idp.example.com".into(),
            idp_sso_url: "https://idp.example.com/sso".into(),
            idp_x509_cert_pem: ok_pem().into(),
            allow_idp_initiated: false,
            trust_email_assertion: false,
            default_role: "member".into(),
            attribute_mapping: AttributeMapping::default(),
            sp_signing_key: None,
            sp_signing_alg: SpSigningAlg::default(),
            sp_signing_cert_pem: None,
        };
        cfg.validate().expect("valid");
    }

    #[test]
    fn defaults_round_trip_through_serde() {
        let v: serde_json::Value = serde_json::json!({
            "config_version": 1,
            "idp_entity_id": "https://idp.example.com",
            "idp_sso_url": "https://idp.example.com/sso",
            "idp_x509_cert_pem": ok_pem(),
        });
        let cfg = SamlConfigV1::from_jsonb(&v).expect("parse");
        assert_eq!(cfg.attribute_mapping.email, "mail");
        assert_eq!(cfg.attribute_mapping.given_name, "givenName");
        assert_eq!(cfg.attribute_mapping.family_name, "sn");
        assert!(cfg.attribute_mapping.groups.is_none());
        assert!(!cfg.allow_idp_initiated);
        assert!(!cfg.trust_email_assertion);
        assert_eq!(cfg.default_role, "member");
        assert_eq!(cfg.sp_signing_alg, SpSigningAlg::Rsa2048);
        assert!(cfg.sp_signing_key.is_none());
        assert!(cfg.sp_signing_cert_pem.is_none());
    }
}
