// SPDX-License-Identifier: AGPL-3.0-or-later

//! Signing-key provider port.
//!
//! Identity uses [`KeyProvider`] for JWT signing (today, in-process keys)
//! and SAML SP signing-key generation. The KMS layer will replace the default
//! impl with a KMS-backed provider; the trait shape is forward-compatible.

use async_trait::async_trait;

/// Signing-key provider.
///
/// Implementations must scope keys by both `key_id` (rotation slot) and
/// `purpose` (e.g. `"session"`, `"saml-sp"`) so a single provider can
/// host multiple key materials without collision.
///
/// Signature outputs carry their algorithm tag so verifiers can never
/// mismatch (RFC 8725 §2.1 — alg-confusion is a documented JWS class-A
/// vulnerability when the signed `alg` header is trusted blindly).
#[async_trait]
pub trait KeyProvider: Send + Sync + 'static {
    /// Sign arbitrary bytes with the named key. The returned [`Signature`]
    /// carries the algorithm + key id used so verifiers cannot confuse
    /// outputs across rotation periods.
    async fn sign(&self, key_id: &str, payload: &[u8]) -> Result<Signature, KeyProviderError>;

    /// Return the active signing-key handle for the given purpose. Used
    /// by metadata exporters + JWKS publishers to surface the public half.
    async fn active_key(&self, purpose: &str) -> Result<KeyHandle, KeyProviderError>;
}

/// Signed-output bundle returned by [`KeyProvider::sign`].
///
/// Bundling `algorithm` + `key_id` with the raw bytes prevents the
/// alg-confusion class of attacks: a verifier holding a [`KeyHandle`]
/// from a different rotation period checks the bundled algorithm
/// against the one it expects and rejects mismatches before computing
/// the verification.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Algorithm used to produce `bytes` (e.g. [`SignatureAlgorithm::Rs256`]).
    pub algorithm: SignatureAlgorithm,
    /// Stable key identifier (rotation slot) that produced this signature.
    pub key_id: String,
    /// Raw signature bytes in the algorithm's canonical encoding.
    pub bytes: Vec<u8>,
}

/// Closed enum of signing algorithms the platform supports.
///
/// The lack of `#[non_exhaustive]` is intentional: every verifier MUST
/// exhaust every variant on every code path so a future algorithm cannot
/// be silently skipped via a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSA-PKCS1v1.5 / SHA-256. Default JWS signing for v0.1.
    Rs256,
    /// ECDSA / P-256 / SHA-256.
    Es256,
    /// `EdDSA` / Ed25519. Preferred for new deployments per RFC 8037.
    EdDsa,
}

impl SignatureAlgorithm {
    /// JWS / JWA registered name as it appears in the protected header.
    #[must_use]
    pub const fn jws_name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }
}

/// Public-key descriptor returned by [`KeyProvider::active_key`].
#[derive(Debug, Clone)]
pub struct KeyHandle {
    /// Stable key identifier (rotation slot).
    pub key_id: String,
    /// Algorithm bound to this key. Verifiers MUST compare this against
    /// [`Signature::algorithm`] before computing the verification.
    pub algorithm: SignatureAlgorithm,
    /// PEM-encoded public key.
    pub public_key_pem: String,
}

/// Failure modes the provider may surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyProviderError {
    /// `key_id` is not known to this provider.
    #[error("unknown key id: {0}")]
    UnknownKey(String),
    /// `purpose` is not registered with this provider.
    #[error("unknown purpose: {0}")]
    UnknownPurpose(String),
    /// Backend (HSM / KMS / on-disk) error.
    #[error("provider error: {0}")]
    Provider(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(KeyProvider);
    assert_impl_all!(KeyHandle: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(Signature: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(
        SignatureAlgorithm: Send,
        Sync,
        Copy,
        Clone,
        PartialEq,
        Eq,
        std::hash::Hash
    );
    assert_impl_all!(KeyProviderError: Send, Sync, std::error::Error);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<KeyProviderError>();
        require_static::<Signature>();
        require_static::<KeyHandle>();
    };

    #[test]
    fn jws_name_round_trips_every_algorithm() {
        let variants = [
            SignatureAlgorithm::Rs256,
            SignatureAlgorithm::Es256,
            SignatureAlgorithm::EdDsa,
        ];
        for variant in variants {
            // Closed-enum coverage check: exhaustive match.
            match variant {
                SignatureAlgorithm::Rs256
                | SignatureAlgorithm::Es256
                | SignatureAlgorithm::EdDsa => {}
            }
            // JWS names are stable per RFC 7518.
            let expected = match variant {
                SignatureAlgorithm::Rs256 => "RS256",
                SignatureAlgorithm::Es256 => "ES256",
                SignatureAlgorithm::EdDsa => "EdDSA",
            };
            assert_eq!(variant.jws_name(), expected);
        }
    }
}
