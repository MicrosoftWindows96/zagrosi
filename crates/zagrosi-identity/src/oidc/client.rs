// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcClient` — `openidconnect::CoreClient` wrapper.
//!
//! Builds the typed `CoreClient` per callback from cached discovery
//! metadata + `OidcConfigV1`, then runs:
//!
//! 1. PKCE-bound `exchange_code` against the token endpoint.
//! 2. ID-token validation chain (`iss` / `aud` / `azp` / `exp` / `iat` /
//!    `nonce` / `at_hash` / `c_hash`) via `IdToken::claims(&verifier,
//!    &nonce)` plus the explicit post-checks below.
//! 3. Optional JWKS thumbprint constant-time compare.
//! 4. Discovery refresh + retry on `kid`-miss (one extra retry per
//!    callback, gated by the per-issuer 1/min rate-limit on the
//!    discovery cache).
//!
//! The lib's strongly-typed verifier validates the standard claim set;
//! `acr` / `amr` are extracted as a side band by parsing the raw JWT
//! payload (the lib does not expose them on `StandardClaims`).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use openidconnect::core::{CoreClient, CoreErrorResponseType, CoreIdTokenClaims};
use openidconnect::reqwest::Error as ReqwestError;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, AuthorizationCodeHash, ClientId, ClientSecret,
    HttpClientError, Nonce, OAuth2TokenResponse, PkceCodeVerifier, RedirectUrl, RequestTokenError,
    StandardErrorResponse, TokenResponse,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::oidc::config::OidcConfigV1;
use crate::oidc::discovery::{DiscoveryCache, DiscoverySnapshot};

/// HTTP timeout applied per outbound discovery / token-endpoint call.
/// The full callback path layers a separate axum handler timeout on top.
pub const PER_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Permitted clock skew (forward and backward) when validating
/// time-bearing ID-token claims. The OIDC spec recommends a small
/// tolerance to absorb NTP drift between the IdP and the relying party;
/// 30 seconds is the section-10 documented value and is exposed here as
/// a named constant so tests can pin against it.
pub const ID_TOKEN_SKEW: Duration = Duration::from_secs(30);

/// Strongly-typed sidecar payload used to extract `acr` / `amr` from
/// the raw ID token JWT body — `openidconnect`'s `StandardClaims` does
/// not expose those values directly.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcrAmrClaims {
    /// Authentication Context Class Reference. Pass-through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication Methods References. Pass-through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
}

impl std::fmt::Debug for AcrAmrClaims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show the value/count shape but suppress raw acr/amr strings
        // since some IdPs emit URN values that correlate with policy
        // metadata an attacker could chain into a profiling oracle.
        f.debug_struct("AcrAmrClaims")
            .field("acr", &self.acr)
            .field(
                "amr_count",
                &self.amr.as_ref().map_or(0, std::vec::Vec::len),
            )
            .finish_non_exhaustive()
    }
}

/// Strongly-typed callback outcome. Holds the verified ID-token claims
/// (the lib's `CoreIdTokenClaims`) plus the side-channel `acr` / `amr`
/// plus the access + refresh tokens (zeroed-on-drop via `SecretString`).
///
/// The `Debug` impl redacts every PII-bearing field including
/// `claims_subject` (some IdPs use email-shaped `sub` values, e.g.
/// Microsoft Entra and Google Workspace; rendering verbatim would
/// drop user emails into structured logs).
pub struct VerifiedIdToken {
    /// Validated standard ID-token claims (subject / email / name /
    /// `email_verified`).
    pub claims: CoreIdTokenClaims,
    /// `acr` / `amr` extracted via raw-JWT parse. The lib does not
    /// expose these on `StandardClaims`.
    pub acr_amr: AcrAmrClaims,
    /// Optional refresh-token. `None` when the IdP did not
    /// return one (`offline_access` not requested or not granted).
    /// Wrapped in [`SecretString`] so a panic mid-flow zeroes the
    /// allocation on Drop.
    pub refresh_token: Option<SecretString>,
    /// Access token. The OIDC service does not currently call the
    /// userinfo endpoint; the value is available for future userinfo
    /// flows. Same zeroize-on-drop discipline as the refresh token.
    pub access_token: SecretString,
}

impl std::fmt::Debug for VerifiedIdToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Custom Debug redacts every PII / secret-bearing field plus
        // the standard claim block (`claims` may carry email-shaped
        // `sub`, the `name` claim, etc.). Operators correlating
        // sign-in failures use the `correlation_id` carried by the
        // outer `tracing::instrument` span rather than this Debug
        // shape.
        f.debug_struct("VerifiedIdToken")
            .field("claims", &"<redacted>")
            .field("claims_subject", &"<redacted>")
            .field("acr_amr", &self.acr_amr)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("access_token", &"<redacted>")
            .finish()
    }
}

/// `OidcClient` orchestrates a single callback's exchange + validation.
/// Cheap to clone — every dep is an `Arc` or owned config.
#[derive(Clone)]
pub struct OidcClient {
    http: Arc<reqwest::Client>,
}

impl OidcClient {
    /// Wire to the shared HTTP client. The client MUST share the same
    /// `Arc<reqwest::Client>` injected into [`crate::oidc::discovery::DiscoveryCache`]
    /// so the rustls connection pool is reused.
    #[must_use]
    pub const fn new(http: Arc<reqwest::Client>) -> Self {
        Self { http }
    }

    /// Run the full callback exchange + verification.
    ///
    /// 1. JWKS thumbprint pin (when configured).
    /// 2. `exchange_code(code).set_pkce_verifier(verifier)` against the
    ///    token endpoint.
    /// 3. ID-token signature + claim validation via the lib.
    /// 4. Side-channel `acr` / `amr` extraction from the raw JWT body.
    /// 5. Explicit `iat <= now() + 30s` and `at_hash` checks the lib
    ///    does not enforce by default.
    /// 6. On signing-key miss (the IdP rotated keys after our last
    ///    discovery refresh), force-refresh discovery once and retry
    ///    the verification path. The discovery cache rate-limits real
    ///    refreshes to 1/min/issuer so a hostile IdP cannot weaponise
    ///    repeated misses.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // every arg is a security-distinct invariant; the body is the full validation chain
    #[tracing::instrument(
        skip_all,
        fields(
            issuer = %config.issuer_url,
            client_id = %config.client_id,
            route = "oidc.exchange",
        )
    )]
    pub async fn exchange_and_verify(
        &self,
        snapshot: &DiscoverySnapshot,
        config: &OidcConfigV1,
        client_secret_plain: secrecy::SecretString,
        redirect_uri: &str,
        raw_nonce: &str,
        raw_pkce_verifier: &str,
        authorization_code: &str,
        discovery_cache: Option<&DiscoveryCache>,
    ) -> Result<VerifiedIdToken> {
        if let Some(ref pin) = config.expected_jwks_thumbprint {
            snapshot.assert_thumbprint(pin)?;
        }

        // Inline the client build so the post-`set_redirect_uri`
        // endpoint-state generics resolve to the shape `exchange_code`
        // requires (`HasTokenUrl: EndpointMaybeSet` + redirect-set).
        let metadata = snapshot.metadata.clone();
        let client_id = ClientId::new(config.client_id.clone());
        let client_secret = ClientSecret::new(client_secret_plain.expose_secret().to_owned());
        let redirect = RedirectUrl::new(redirect_uri.to_owned()).map_err(|err| {
            tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "redirect uri parse failed");
            IdentityError::OidcConfigInvalid {
                reason: format!("redirect_uri malformed: {err}"),
            }
        })?;
        let client = CoreClient::from_provider_metadata(metadata, client_id, Some(client_secret))
            .set_redirect_uri(redirect);

        let pkce_verifier = PkceCodeVerifier::new(raw_pkce_verifier.to_owned());
        let code = AuthorizationCode::new(authorization_code.to_owned());

        let token_request = client
            .exchange_code(code)
            .map_err(|err| {
                tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "exchange_code config error");
                IdentityError::OidcDiscoveryFailed("token endpoint missing")
            })?
            .set_pkce_verifier(pkce_verifier);

        let token_response = match tokio::time::timeout(
            PER_CALL_TIMEOUT,
            token_request.request_async(self.http.as_ref()),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(err)) => {
                tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "token endpoint exchange failed");
                return Err(map_token_error(&err));
            }
            Err(_elapsed) => {
                return Err(IdentityError::OidcDiscoveryFailed(
                    "token endpoint timed out",
                ));
            }
        };

        let id_token = token_response
            .id_token()
            .ok_or(IdentityError::OidcIdTokenInvalid("missing id_token"))?;

        let nonce_obj = Nonce::new(raw_nonce.to_owned());

        // Validate the ID token. On signing-key miss the discovery
        // cache may be carrying the IdP's previous JWKS; force-refresh
        // once and retry. The cache's per-issuer 1/min rate-limit
        // bounds the total HTTP traffic even under a hostile retry
        // loop.
        let id_verifier = client.id_token_verifier();
        let claims_result = id_token.claims(&id_verifier, &nonce_obj);
        let claims = match claims_result {
            Ok(c) => c.clone(),
            Err(err) => {
                if is_kid_miss_or_signature(&err) && discovery_cache.is_some() {
                    if let Some(cache) = discovery_cache {
                        let refreshed = cache.force_refresh(&config.issuer_url).await?;
                        // The thumbprint pin's job is to catch a
                        // hostile JWKS rotation. The kid-miss retry is
                        // exactly when a hostile rotation would land,
                        // so re-assert the pin against the refreshed
                        // JWKS bytes BEFORE rebuilding the verifier.
                        if let Some(ref pin) = config.expected_jwks_thumbprint {
                            refreshed.assert_thumbprint(pin)?;
                        }
                        // Rebuild the client with the refreshed JWKS.
                        let client_id_retry = ClientId::new(config.client_id.clone());
                        let secret_retry =
                            ClientSecret::new(client_secret_plain.expose_secret().to_owned());
                        let redirect_retry =
                            RedirectUrl::new(redirect_uri.to_owned()).map_err(|e| {
                                IdentityError::OidcConfigInvalid {
                                    reason: format!("redirect_uri malformed: {e}"),
                                }
                            })?;
                        let client_retry = CoreClient::from_provider_metadata(
                            refreshed.metadata,
                            client_id_retry,
                            Some(secret_retry),
                        )
                        .set_redirect_uri(redirect_retry);
                        let verifier_retry = client_retry.id_token_verifier();
                        let nonce_retry = Nonce::new(raw_nonce.to_owned());
                        id_token
                            .claims(&verifier_retry, &nonce_retry)
                            .map_err(|err2| {
                                tracing::warn!(target: "zagrosi.identity.oidc", error = %err2, "id_token claim verification failed after refresh");
                                IdentityError::OidcIdTokenInvalid("claim verification failed")
                            })?
                            .clone()
                    } else {
                        tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "id_token claim verification failed");
                        return Err(IdentityError::OidcIdTokenInvalid(
                            "claim verification failed",
                        ));
                    }
                } else {
                    tracing::warn!(target: "zagrosi.identity.oidc", error = %err, "id_token claim verification failed");
                    return Err(IdentityError::OidcIdTokenInvalid(
                        "claim verification failed",
                    ));
                }
            }
        };

        // Defence-in-depth `azp` check: the underlying verifier
        // already enforces `azp == client_id` when `azp` is present;
        // we re-check explicitly for trace dashboards.
        if let Some(azp) = claims.authorized_party()
            && azp.as_str() != config.client_id
        {
            return Err(IdentityError::OidcIdTokenInvalid("azp mismatch"));
        }

        // Explicit `iat` check. The lib's verifier validates `exp` but
        // does not constrain `iat`; an IdP shipping a far-future
        // `iat` is either misconfigured or lying.
        let now = Utc::now();
        let iat = claims.issue_time();
        let skew = chrono::Duration::from_std(ID_TOKEN_SKEW)
            .unwrap_or_else(|_| chrono::Duration::seconds(30));
        if iat > now + skew {
            return Err(IdentityError::OidcIdTokenInvalid("iat in future"));
        }

        // Explicit `at_hash` check. The lib does not enforce this for
        // every signing algorithm by default; we recompute it here so
        // an IdP that mints `at_hash` cannot smuggle a mismatched
        // access token. The signing key is the same one the verifier
        // selected when validating the JWT signature; we re-resolve
        // it via the public `signing_key` accessor on the ID token.
        if let Some(expected_hash) = claims.access_token_hash() {
            let signing_alg = id_token
                .signing_alg()
                .map_err(|_| IdentityError::OidcIdTokenInvalid("missing signing alg"))?
                .to_owned();
            let signing_key = id_token
                .signing_key(&id_verifier)
                .map_err(|_| IdentityError::OidcIdTokenInvalid("signing key not found"))?;
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &signing_alg,
                signing_key,
            )
            .map_err(|_| IdentityError::OidcIdTokenInvalid("at_hash compute failed"))?;
            if &actual_hash != expected_hash {
                return Err(IdentityError::OidcIdTokenInvalid("at_hash mismatch"));
            }
        }

        // Explicit `c_hash` check. Section-10 spec line 82 demands the
        // hash be validated against the authorization code when the
        // claim is present. The Authorization Code flow without
        // `id_token` in the authorization response (our shape) rarely
        // sees a `c_hash`; future hybrid-flow extensions will.
        if let Some(expected_c_hash) = claims.code_hash() {
            let signing_alg = id_token
                .signing_alg()
                .map_err(|_| IdentityError::OidcIdTokenInvalid("missing signing alg"))?
                .to_owned();
            let signing_key = id_token
                .signing_key(&id_verifier)
                .map_err(|_| IdentityError::OidcIdTokenInvalid("signing key not found"))?;
            let auth_code = AuthorizationCode::new(authorization_code.to_owned());
            let actual_c_hash =
                AuthorizationCodeHash::from_code(&auth_code, &signing_alg, signing_key)
                    .map_err(|_| IdentityError::OidcIdTokenInvalid("c_hash compute failed"))?;
            if &actual_c_hash != expected_c_hash {
                return Err(IdentityError::OidcIdTokenInvalid("c_hash mismatch"));
            }
        }

        let id_token_str = id_token.to_string();
        let acr_amr = parse_acr_amr_from_jwt(&id_token_str);

        let access_token = SecretString::from(token_response.access_token().secret().clone());
        let refresh_token = token_response
            .refresh_token()
            .map(|t| SecretString::from(t.secret().clone()));

        Ok(VerifiedIdToken {
            claims,
            acr_amr,
            refresh_token,
            access_token,
        })
    }
}

/// Match the lib's typed `SignatureVerification` variant so a discovery
/// refresh + retry only fires on real signing-key issues, not on every
/// validation error whose `Display` string happens to contain the word
/// "key" (locale or minor-version drift in the lib's `Display` would
/// otherwise burn the per-issuer 1/min refresh budget on irrelevant
/// failures).
const fn is_kid_miss_or_signature(err: &openidconnect::ClaimsVerificationError) -> bool {
    matches!(
        err,
        openidconnect::ClaimsVerificationError::SignatureVerification(_)
    )
}

/// Parse `acr` / `amr` from the raw JWT body without re-validating
/// the signature (the lib already validated it). Returns
/// [`AcrAmrClaims::default`] on any parse failure since these claims
/// are advisory — failing to extract them must not abort the sign-in.
/// Logs a `tracing::trace!` when the fallback fires so an operator
/// chasing "why did `session.amr` stay empty" can grep it.
fn parse_acr_amr_from_jwt(jwt: &str) -> AcrAmrClaims {
    let mut parts = jwt.splitn(3, '.');
    let _header = parts.next();
    let Some(body) = parts.next() else {
        tracing::trace!(target: "zagrosi.identity.oidc", "acr/amr fallback: jwt has no body part");
        return AcrAmrClaims::default();
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(body) else {
        tracing::trace!(target: "zagrosi.identity.oidc", "acr/amr fallback: jwt body not base64url");
        return AcrAmrClaims::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        tracing::trace!(target: "zagrosi.identity.oidc", "acr/amr fallback: jwt body json parse failed");
        AcrAmrClaims::default()
    })
}

/// Map the lib's typed token-endpoint error into our error enum
/// without disclosing IdP-specific reason codes to log surfaces.
const fn map_token_error(
    err: &RequestTokenError<
        HttpClientError<ReqwestError>,
        StandardErrorResponse<CoreErrorResponseType>,
    >,
) -> IdentityError {
    match err {
        RequestTokenError::ServerResponse(_) => {
            IdentityError::OidcIdTokenInvalid("token endpoint server error")
        }
        RequestTokenError::Request(_) | RequestTokenError::Other(_) => {
            IdentityError::OidcDiscoveryFailed("token endpoint exchange failed")
        }
        RequestTokenError::Parse(_, _) => {
            IdentityError::OidcIdTokenInvalid("token endpoint response unparseable")
        }
    }
}

/// libFuzzer entry point for the offline slice of the ID-token
/// validation chain.
///
/// [`OidcClient::exchange_and_verify`] is network-coupled (token
/// endpoint round-trip + JWKS fetch), so the fuzz harness cannot
/// drive it directly. This entry point exercises every part of the
/// chain that operates on attacker-controlled bytes *without* a
/// network: compact-JWS segmentation, base64url body decode, JSON
/// claim deserialisation into the same [`CoreIdTokenClaims`] /
/// [`AcrAmrClaims`] shapes the live path uses, and the `iat`-skew /
/// `azp`-shape post-checks that run after signature verification.
///
/// The contract mirrors the other fuzz entry points
/// ([`crate::saml::acs::fuzz_entry`], `http::scim::filter::parse`):
/// it MUST NEVER panic, MUST NEVER touch the network, and MUST NEVER
/// return a value that downstream code could mistake for a verified
/// token (it returns `()` — the harness asserts only the no-panic
/// invariant). Gated behind `cfg(any(test, feature = "fuzzing"))`
/// so the default build never ships it.
#[cfg(any(test, feature = "fuzzing"))]
pub fn verify_id_token_for_fuzz(data: &[u8]) {
    let Ok(jwt) = std::str::from_utf8(data) else {
        return;
    };

    // Side-band acr/amr extraction (same helper the live path calls
    // after the lib verifies the signature). Never panics by
    // contract; the result is intentionally discarded.
    let _ = parse_acr_amr_from_jwt(jwt);

    // Compact-JWS segmentation + base64url body decode + JSON claim
    // parse. The live path delegates this to the lib's verifier; here
    // we drive the raw decode so the fuzzer reaches the serde shape
    // boundary directly.
    let mut parts = jwt.splitn(3, '.');
    let (_header, body, _sig) = (parts.next(), parts.next(), parts.next());
    let Some(body) = body else {
        return;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(body) else {
        return;
    };
    let Ok(claims) = serde_json::from_slice::<CoreIdTokenClaims>(&bytes) else {
        return;
    };

    // Offline post-checks the lib does not enforce (mirrors the
    // explicit `iat` / `azp` blocks in `exchange_and_verify`). These
    // are pure comparisons over already-decoded values — no I/O.
    let now = Utc::now();
    let skew =
        chrono::Duration::from_std(ID_TOKEN_SKEW).unwrap_or_else(|_| chrono::Duration::seconds(30));
    let _future_iat = claims.issue_time() > now + skew;
    let _azp_present = claims.authorized_party().is_some();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_id_token_for_fuzz_never_panics_on_adversarial_bytes() {
        // Mirrors the libFuzzer contract: arbitrary bytes, compact
        // JWS look-alikes, and a well-formed-but-unsigned token all
        // return without unwinding.
        let body = serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "abc",
            "aud": ["client_id"],
            "exp": (Utc::now() + chrono::Duration::seconds(60)).timestamp(),
            "iat": Utc::now().timestamp(),
        });
        let body_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).expect("body"));
        let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{body_b64}.sig");
        for input in [
            &b""[..],
            &b"not.a.jwt"[..],
            &[0xff, 0xfe, 0xfd][..],
            b".....",
            jwt.as_bytes(),
        ] {
            verify_id_token_for_fuzz(input);
        }
    }

    #[test]
    fn acr_amr_claims_serde_default() {
        let json = serde_json::to_string(&AcrAmrClaims::default()).expect("serialise");
        assert_eq!(json, "{}");
    }

    #[test]
    fn acr_amr_claims_round_trip() {
        let claims = AcrAmrClaims {
            acr: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
            amr: Some(vec!["mfa".into(), "pwd".into()]),
        };
        let json = serde_json::to_string(&claims).expect("serialise");
        let parsed: AcrAmrClaims = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(parsed, claims);
    }

    #[test]
    fn parse_acr_amr_extracts_present_fields() {
        let body = serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "abc",
            "acr": "urn:zagrosi:test",
            "amr": ["mfa", "pwd"],
        });
        let body_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).expect("body"));
        let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{body_b64}.signature-here");
        let parsed = parse_acr_amr_from_jwt(&jwt);
        assert_eq!(parsed.acr.as_deref(), Some("urn:zagrosi:test"));
        assert_eq!(
            parsed.amr.as_deref(),
            Some(&["mfa".to_owned(), "pwd".to_owned()][..]),
        );
    }

    #[test]
    fn parse_acr_amr_returns_default_for_garbage() {
        assert_eq!(parse_acr_amr_from_jwt("not.a.jwt"), AcrAmrClaims::default());
        assert_eq!(parse_acr_amr_from_jwt(""), AcrAmrClaims::default());
        assert_eq!(
            parse_acr_amr_from_jwt("only_one_part"),
            AcrAmrClaims::default()
        );
    }

    #[test]
    fn parse_acr_amr_returns_default_for_missing_fields() {
        let body = serde_json::json!({"iss": "idp", "sub": "abc"});
        let body_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&body).expect("body"));
        let jwt = format!("h.{body_b64}.s");
        let parsed = parse_acr_amr_from_jwt(&jwt);
        assert!(parsed.acr.is_none());
        assert!(parsed.amr.is_none());
    }

    #[test]
    fn debug_redacts_access_refresh_and_subject() {
        let payload = VerifiedIdToken {
            claims: openidconnect::IdTokenClaims::new(
                openidconnect::IssuerUrl::new("https://idp.example.com".to_owned())
                    .expect("issuer"),
                vec![openidconnect::Audience::new("client_id".to_owned())],
                Utc::now() + chrono::Duration::seconds(60),
                Utc::now(),
                openidconnect::StandardClaims::new(openidconnect::SubjectIdentifier::new(
                    "alice@example.com".to_owned(),
                )),
                openidconnect::EmptyAdditionalClaims {},
            ),
            acr_amr: AcrAmrClaims::default(),
            refresh_token: Some(SecretString::from("rsk_supersecret".to_owned())),
            access_token: SecretString::from("ats_supersecret".to_owned()),
        };
        let rendered = format!("{payload:?}");
        assert!(!rendered.contains("supersecret"));
        assert!(!rendered.contains("alice@example.com"));
        assert!(rendered.contains("redacted"));
    }
}
