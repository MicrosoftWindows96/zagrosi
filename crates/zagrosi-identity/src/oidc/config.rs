// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Versioned OIDC client configuration persisted in `org_idps.config`.
//!
//! `OidcConfigV1` is the JSONB shape stored in
//! `org_idps.config WHERE protocol = 'oidc'`. The `org_idps.config_version`
//! discriminator is bumped when a field becomes non-optional or
//! changes meaning; `OidcConfigV1` corresponds to version `1`.
//!
//! Secret material (`client_secret`) lives sealed inside the same
//! JSONB blob via the `crypto::Secrets` envelope.
//! Plaintext secrets never persist; opening the envelope is the
//! single chokepoint for callers that need the raw client secret.

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use url::Url;

use crate::crypto::{Envelope, Secrets};
use crate::error::{IdentityError, Result};

/// The `org_idps.config_version` value that marks a row as carrying
/// the [`OidcConfigV1`] shape. Bump when the shape changes; future
/// `OidcConfigV2` lands as a sibling type and migration step.
pub const OIDC_CONFIG_VERSION_V1: i16 = 1;

/// Default OAuth scopes requested at the IdP. `openid` is mandatory;
/// `email` and `profile` align with the JIT-provisioning data needs
/// (`StandardClaims::email` / `StandardClaims::name`).
const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];

/// Maximum length of the `client_id` field in characters. RFC 6749
/// gives no explicit bound; this guard prevents an admin from pasting
/// an unbounded blob into the JSONB column.
pub const CLIENT_ID_MAX_LEN: usize = 255;

/// Versioned JSONB-resident OIDC client config.
///
/// The wrapper [`StoredOidcConfig`] adds the `version` discriminator
/// at the top of the JSON; downstream readers branch on `version`
/// before deserialising the body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OidcConfigV1 {
    /// Pinned issuer URL. Constant-time matched against the IdP's
    /// `iss` claim and the RFC 9207 `iss` query parameter.
    #[serde(rename = "issuer_url")]
    pub issuer_url: Url,
    /// OAuth client identifier registered at the IdP.
    pub client_id: String,
    /// AES-256-GCM-sealed client secret. Opened on the hot
    /// callback path via [`OidcConfigV1::client_secret`].
    pub client_secret: SealedSecret,
    /// Optional override; default derived at runtime by the start
    /// handler: `ZAGROSI_BASE_URL + "/v1/auth/oidc/" + slug + "/callback"`.
    #[serde(default)]
    pub redirect_uri_override: Option<Url>,
    /// OAuth scopes requested at the IdP. MUST contain `openid`. The
    /// default (`DEFAULT_SCOPES`) is applied when the JSON omits the field.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Per-IdP claim-to-user-field overrides. Reserved for future SSO
    /// federation; v0.1 ignores the contents (the JIT mapper reads
    /// `email`, `name`, `email_verified` from `StandardClaims`).
    #[serde(default)]
    pub attribute_mapping: AttributeMapping,
    /// Optional defence-in-depth JWKS pin. SHA-256 of the discovery
    /// JWKS JSON (`jwks_uri` document body) rendered as 64 hex chars.
    #[serde(default)]
    pub expected_jwks_thumbprint: Option<String>,
    /// JIT trust gate override. `false` (default) requires
    /// `id_token.email_verified == true` for JIT user creation.
    #[serde(default)]
    pub allow_unverified_email_jit: bool,
    /// Role assigned to JIT-provisioned `user_org_memberships`. `None`
    /// falls back to the org's default member role (`"member"` in v0.1).
    #[serde(default)]
    pub default_role: Option<String>,
    /// Whether the OIDC client requests `offline_access`. Refresh-token
    /// rotation + chain replay-detection is built either way; this gate
    /// only controls whether the start handler sends the `offline_access`
    /// scope. Default `false`: many enterprise IdPs do not require it.
    #[serde(default)]
    pub enable_refresh: bool,
}

/// Default constructor for the `scopes` JSON field.
fn default_scopes() -> Vec<String> {
    DEFAULT_SCOPES.iter().map(|&s| s.to_owned()).collect()
}

/// Per-IdP claim → user-field mapping. v0.1 reserves the shape for
/// the upcoming multi-IdP federation layer; today only the
/// `email_claim` / `display_name_claim` overrides are honoured (and
/// the JIT path falls back to the OIDC standard claims when these are
/// `None`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttributeMapping {
    /// Claim path that supplies the JIT user's email. Default: standard
    /// `email` claim.
    #[serde(default)]
    pub email_claim: Option<String>,
    /// Claim path that supplies the JIT user's display name. Default:
    /// standard `name` claim falling back to the local-part of the email.
    #[serde(default)]
    pub display_name_claim: Option<String>,
}

/// Newtype wrapping a [`crate::crypto::Envelope`] in the JSONB shape so
/// the OIDC client secret round-trips through serde without exposing
/// the raw bytes to anything outside the [`OidcConfigV1::client_secret`]
/// accessor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedSecret(Envelope);

impl SealedSecret {
    /// Wrap a freshly sealed envelope.
    #[must_use]
    pub const fn from_envelope(env: Envelope) -> Self {
        Self(env)
    }

    /// Borrow the envelope (e.g. for serialisation in tests).
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.0
    }
}

impl OidcConfigV1 {
    /// Validate and store. Returns the rendered JSON value ready for
    /// `OrgScoped::<OrgIdpRepo>::create`.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OidcConfigInvalid`] when:
    ///   - `issuer_url` is not HTTPS, has a fragment, or has user-info.
    ///   - `client_id` is empty or exceeds [`CLIENT_ID_MAX_LEN`].
    ///   - `scopes` does not contain `"openid"`.
    ///   - `expected_jwks_thumbprint` is set but is not 64 lower-case
    ///     hex characters.
    pub fn validate(&self) -> Result<()> {
        if self.issuer_url.scheme() != "https" {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "issuer_url must use https".into(),
            });
        }
        if self.issuer_url.fragment().is_some() {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "issuer_url must not contain a fragment".into(),
            });
        }
        if !self.issuer_url.username().is_empty() || self.issuer_url.password().is_some() {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "issuer_url must not embed credentials".into(),
            });
        }
        let trimmed = self.client_id.trim();
        if trimmed.is_empty() {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "client_id must not be empty".into(),
            });
        }
        if self.client_id.len() > CLIENT_ID_MAX_LEN {
            return Err(IdentityError::OidcConfigInvalid {
                reason: format!("client_id exceeds {CLIENT_ID_MAX_LEN} characters"),
            });
        }
        if !self.scopes.iter().any(|s| s == "openid") {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "scopes must include `openid`".into(),
            });
        }
        if let Some(ref pin) = self.expected_jwks_thumbprint {
            if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: "expected_jwks_thumbprint must be 64 hex chars".into(),
                });
            }
            if pin.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: "expected_jwks_thumbprint must be lower-case hex".into(),
                });
            }
        }
        if let Some(ref override_uri) = self.redirect_uri_override {
            if override_uri.scheme() != "https" {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: "redirect_uri_override must use https".into(),
                });
            }
            if override_uri.fragment().is_some() {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: "redirect_uri_override must not contain a fragment".into(),
                });
            }
            if !override_uri.username().is_empty() || override_uri.password().is_some() {
                return Err(IdentityError::OidcConfigInvalid {
                    reason: "redirect_uri_override must not embed credentials".into(),
                });
            }
        }
        // The start handler unconditionally adds `offline_access` when
        // `enable_refresh = true`; reject the inverse misconfiguration
        // (scope set, gate off) at write time so an admin's intent is
        // explicit.
        if !self.enable_refresh && self.scopes.iter().any(|s| s == "offline_access") {
            return Err(IdentityError::OidcConfigInvalid {
                reason: "offline_access in scopes requires enable_refresh = true".into(),
            });
        }
        Ok(())
    }

    /// Open the sealed `client_secret` envelope, returning the raw
    /// secret as a [`SecretString`] (zeroed on drop).
    ///
    /// # Errors
    ///
    /// Propagates [`Secrets::open`]: [`IdentityError::UnknownKeyId`]
    /// when the envelope was sealed with an unknown provider,
    /// [`IdentityError::IntegrityError`] when the AEAD tag fails, or
    /// [`IdentityError::MalformedEnvelope`] for wire-shape errors.
    pub fn client_secret(&self, secrets: &Secrets) -> Result<SecretString> {
        let bytes = secrets.open(self.client_secret.envelope())?;
        let s = String::from_utf8(bytes).map_err(|_| IdentityError::OidcConfigInvalid {
            reason: "client_secret plaintext is not valid UTF-8".into(),
        })?;
        Ok(SecretString::from(s))
    }

    /// Render the wrapped value into the JSONB shape stored in
    /// `org_idps.config`.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OidcConfigInvalid`] when serialisation fails
    ///   (extremely unlikely; fields are owned plain types).
    pub fn into_jsonb(self) -> Result<JsonValue> {
        let stored = StoredOidcConfig::V1(self);
        serde_json::to_value(stored).map_err(|err| IdentityError::OidcConfigInvalid {
            reason: format!("config serialisation failed: {err}"),
        })
    }

    /// Parse a JSONB value into [`OidcConfigV1`].
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OidcConfigInvalid`] when the JSON shape is
    ///   not a known `version` discriminant or fails to deserialise
    ///   into the body type.
    pub fn from_jsonb(value: &JsonValue) -> Result<Self> {
        let stored: StoredOidcConfig = serde_json::from_value(value.clone()).map_err(|err| {
            IdentityError::OidcConfigInvalid {
                reason: format!("config deserialisation failed: {err}"),
            }
        })?;
        let StoredOidcConfig::V1(body) = stored;
        body.validate()?;
        Ok(body)
    }
}

/// Serde envelope discriminator for the JSONB shape. Future versions
/// land as additional `V2(OidcConfigV2)` variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "version")]
#[non_exhaustive]
pub enum StoredOidcConfig {
    /// Version 1.
    #[serde(rename = "1")]
    V1(OidcConfigV1),
}

/// Helper used by [`crate::oidc::client`] tests (and by admin write
/// paths once they land) to seal a plaintext client secret without
/// requiring callers to hand-build the envelope.
///
/// # Errors
///
/// Propagates [`Secrets::seal`].
pub fn seal_client_secret(secrets: &Secrets, plaintext: &str) -> Result<SealedSecret> {
    let env = secrets.seal(plaintext.as_bytes())?;
    Ok(SealedSecret::from_envelope(env))
}

/// Convenience constructor used by tests. Production callers should
/// build the [`OidcConfigV1`] directly via the admin write path
/// (forthcoming in section-13).
#[must_use]
pub fn build_minimal_config(
    issuer_url: Url,
    client_id: impl Into<String>,
    sealed: SealedSecret,
) -> OidcConfigV1 {
    OidcConfigV1 {
        issuer_url,
        client_id: client_id.into(),
        client_secret: sealed,
        redirect_uri_override: None,
        scopes: default_scopes(),
        attribute_mapping: AttributeMapping::default(),
        expected_jwks_thumbprint: None,
        allow_unverified_email_jit: false,
        default_role: None,
        enable_refresh: false,
    }
}

/// Compute the SHA-256 thumbprint of a JWKS document. Used both at
/// admin-write time (compute the pin) and at callback time (compare to
/// `OidcConfigV1::expected_jwks_thumbprint`). Output is lower-case hex
/// to match the canonical pin shape.
#[must_use]
pub fn jwks_thumbprint_hex(jwks_json_bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(jwks_json_bytes);
    hex_lower(&digest)
}

/// Lower-case hex without external `hex::encode` to keep the
/// allocation tight and avoid dragging the crate's `format!` impl.
fn hex_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(ALPHABET[usize::from(b >> 4)] as char);
        out.push(ALPHABET[usize::from(b & 0x0f)] as char);
    }
    out
}

/// Test-only helper that fabricates a `SealedSecret` directly from a
/// fresh envelope without going through the seal path. Useful when a
/// test wants to inject a known-bad envelope (wrong key id, etc.).
#[cfg(test)]
#[must_use]
pub(crate) const fn raw_sealed_for_tests(env: Envelope) -> SealedSecret {
    SealedSecret(env)
}

/// Trace-level helper used by integration tests that want to inspect
/// the base64 of the sealed payload (e.g. to diff envelopes across
/// runs). Public to keep the diff logic in test code; production
/// callers should never round-trip the secret through base64 directly.
#[cfg(test)]
#[must_use]
pub(crate) fn base64_envelope(env: &Envelope) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    let json = serde_json::to_vec(env).unwrap_or_default();
    BASE64_STANDARD.encode(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Secrets;

    fn fixture_secrets() -> Secrets {
        Secrets::from_key(Box::new([0x42; 32]))
    }

    fn fixture_config() -> OidcConfigV1 {
        let s = fixture_secrets();
        let sealed = seal_client_secret(&s, "test-client-secret").expect("seal");
        let issuer = "https://idp.example.com/realms/zagrosi"
            .parse()
            .expect("issuer parse");
        build_minimal_config(issuer, "zagrosi", sealed)
    }

    #[test]
    fn validate_accepts_minimal() {
        fixture_config()
            .validate()
            .expect("minimal config is valid");
    }

    #[test]
    fn validate_rejects_http_issuer() {
        let mut cfg = fixture_config();
        cfg.issuer_url = "http://idp.example.com/".parse().expect("parse");
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, IdentityError::OidcConfigInvalid { .. }));
    }

    #[test]
    fn validate_rejects_issuer_fragment() {
        let mut cfg = fixture_config();
        cfg.issuer_url = "https://idp.example.com/#anchor".parse().expect("parse");
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_credentials_in_issuer() {
        let mut cfg = fixture_config();
        cfg.issuer_url = "https://user:pass@idp.example.com/".parse().expect("parse");
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_empty_client_id() {
        let mut cfg = fixture_config();
        cfg.client_id = String::new();
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_overlong_client_id() {
        let mut cfg = fixture_config();
        cfg.client_id = "a".repeat(CLIENT_ID_MAX_LEN + 1);
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_missing_openid_scope() {
        let mut cfg = fixture_config();
        cfg.scopes = vec!["profile".into(), "email".into()];
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_short_thumbprint() {
        let mut cfg = fixture_config();
        cfg.expected_jwks_thumbprint = Some("abcd".into());
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn validate_rejects_uppercase_thumbprint() {
        let mut cfg = fixture_config();
        cfg.expected_jwks_thumbprint = Some("A".repeat(64));
        assert!(matches!(
            cfg.validate().unwrap_err(),
            IdentityError::OidcConfigInvalid { .. }
        ));
    }

    #[test]
    fn jsonb_round_trip() {
        let cfg = fixture_config();
        let json = cfg.clone().into_jsonb().expect("into_jsonb");
        let parsed = OidcConfigV1::from_jsonb(&json).expect("from_jsonb");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn jsonb_round_trip_carries_version_string() {
        let cfg = fixture_config();
        let json = cfg.into_jsonb().expect("into_jsonb");
        assert_eq!(json["version"], serde_json::json!("1"));
    }

    #[test]
    fn jsonb_rejects_numeric_version_discriminator() {
        // Wire-shape lock: numeric `1` must fail to deserialise so a
        // future numeric encoding cannot collide with V1.
        let mut json = fixture_config().into_jsonb().expect("into_jsonb");
        json["version"] = serde_json::json!(1);
        let parsed = OidcConfigV1::from_jsonb(&json);
        assert!(parsed.is_err());
    }

    #[test]
    fn client_secret_round_trip() {
        use secrecy::ExposeSecret;
        let s = fixture_secrets();
        let sealed = seal_client_secret(&s, "round-trip-secret").expect("seal");
        let cfg = build_minimal_config(
            "https://idp.example.com/".parse().expect("issuer"),
            "client",
            sealed,
        );
        let recovered = cfg.client_secret(&s).expect("open");
        assert_eq!(recovered.expose_secret(), "round-trip-secret");
    }

    #[test]
    fn client_secret_with_wrong_key_returns_unknown_key_id() {
        let s = fixture_secrets();
        let sealed = seal_client_secret(&s, "secret").expect("seal");
        let mut env = sealed.envelope().clone();
        env.key_id = "v0.2-kms-fake".into();
        let cfg = build_minimal_config(
            "https://idp.example.com/".parse().expect("issuer"),
            "client",
            raw_sealed_for_tests(env),
        );
        match cfg.client_secret(&s).unwrap_err() {
            IdentityError::UnknownKeyId(_) => {}
            other => panic!("expected UnknownKeyId, got {other:?}"),
        }
    }

    #[test]
    fn jwks_thumbprint_lower_hex_64() {
        let pin = jwks_thumbprint_hex(b"{}");
        assert_eq!(pin.len(), 64);
        assert!(
            pin.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn base64_envelope_helper_does_not_panic() {
        // Pure compile-coverage for the cfg(test) helper.
        let s = fixture_secrets();
        let sealed = seal_client_secret(&s, "x").expect("seal");
        let _ = base64_envelope(sealed.envelope());
    }
}
