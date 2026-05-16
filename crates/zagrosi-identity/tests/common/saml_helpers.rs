// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared fixtures for the SAML integration suite.
//!
//! Spins up a samael-backed test `IdP` that mints valid signed
//! `Response` XML against a per-test self-signed certificate. The
//! fixture also seeds an `orgs` + `org_idps` row matching the
//! `IdP`'s entity id and cert so the SAML service's `acs::handler`
//! can reach a green path end-to-end.

#![allow(dead_code)]
#![allow(unreachable_pub)]

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use samael::crypto::CertificateDer;
use samael::idp::CertificateParams;
use samael::idp::Rsa as SamaelRsa;
use samael::idp::response_builder::ResponseAttribute;
use samael::idp::sp_extractor::RequiredAttribute;
use samael::idp::{IdentityProvider, KeyType};
use samael::schema::Response;
use samael::traits::ToXml;
use sqlx::PgPool;
use uuid::Uuid;

use zagrosi_identity::config::IdentityConfig;
use zagrosi_identity::crypto::Secrets;
use zagrosi_identity::repo::{
    FederatedIdentityRepo, MembershipRepo, NewOrgIdp, OrgIdpRepo, OrgRepo, OrgScoped,
    SamlPendingRepo, SamlReplayRepo, SessionRepo, UserRepo,
};
use zagrosi_identity::saml::acs::AcsDeps;
use zagrosi_identity::saml::authn::AuthnDeps;
use zagrosi_identity::saml::config::{AttributeMapping, EncryptedKey, SamlConfigV1, SpSigningAlg};
use zagrosi_identity::saml::metadata::MetadataDeps;
use zagrosi_identity::saml::{SamlJitProvisioner, SamlService, SamlServiceDeps};
use zagrosi_identity::session::IdentitySessionIssuer;

/// Public base URL the SP advertises in metadata + uses to derive
/// `acs_url` and `entity_id`. Tests inject this verbatim into
/// `IdentityState`-equivalent dependency bundles.
pub const TEST_BASE_URL: &str = "https://sp.test.zagrosi";

/// Org slug seeded into the test fixtures. Picked to be short and
/// stable across the integration suite.
pub const TEST_ORG_SLUG: &str = "acme";

/// `IdP` entity id used by the test `IdP` — the SP pins this against
/// the `Issuer/@Value` field of every received `Response` /
/// `Assertion`.
pub const TEST_IDP_ENTITY_ID: &str = "https://idp.test.zagrosi/sso";

/// Test `IdP`. Owns the signing keypair + cert; produces signed
/// `Response` XML against caller-provided audiences + recipients.
pub struct TestIdp {
    /// Underlying samael identity provider.
    provider: IdentityProvider,
    /// DER-encoded self-signed certificate.
    pub cert_der: CertificateDer,
    /// PEM-rendered certificate (for inserting into
    /// [`SamlConfigV1::idp_x509_cert_pem`]).
    pub cert_pem: String,
    /// Entity id pinned in the `IdP` `Issuer` element + the SP's
    /// stored config.
    pub entity_id: String,
}

impl TestIdp {
    /// Generate a fresh RSA-2048 keypair + self-signed cert valid
    /// for 30 days.
    pub fn new() -> Self {
        Self::with_entity_id(TEST_IDP_ENTITY_ID)
    }

    /// Generate a fresh keypair + cert under a caller-supplied
    /// entity id (used by the cross-tenant tests that need a
    /// distinct issuer).
    // test fixture: `expect` panics surface keygen/cert setup
    // failure as a test failure (the intended behaviour here).
    #[allow(clippy::expect_used)]
    pub fn with_entity_id(entity_id: &str) -> Self {
        let provider = IdentityProvider::generate_new(KeyType::Rsa(SamaelRsa::Rsa2048))
            .expect("test idp keygen");
        let cert_der = provider
            .create_certificate(&CertificateParams {
                common_name: entity_id,
                issuer_name: entity_id,
                days_until_expiration: 30,
            })
            .expect("test idp cert");
        let cert_pem = der_to_pem(cert_der.der_data());
        Self {
            provider,
            cert_der,
            cert_pem,
            entity_id: entity_id.to_owned(),
        }
    }

    /// Sign an assertion against `acs_url`, `audience`, and an
    /// `in_response_to` request id. Returns the signed Response
    /// (samael domain object).
    // test fixture: `expect` panics surface a signing failure as a
    // test failure (the intended behaviour here).
    #[allow(clippy::expect_used)]
    pub fn sign_response(
        &self,
        name_id: &str,
        audience: &str,
        acs_url: &str,
        in_response_to: &str,
        attributes: &[(&str, &str)],
    ) -> Response {
        let attr_vec: Vec<ResponseAttribute<'_>> = attributes
            .iter()
            .map(|(name, value)| ResponseAttribute {
                required_attribute: RequiredAttribute {
                    name: (*name).to_owned(),
                    format: None,
                },
                value,
            })
            .collect();
        self.provider
            .sign_authn_response(
                &self.cert_der,
                name_id,
                audience,
                acs_url,
                &self.entity_id,
                in_response_to,
                &attr_vec,
            )
            .expect("sign authn response")
    }

    /// Sign a Response and return the base64-encoded XML ready for
    /// the form-POST binding.
    // test fixture: `expect` panics surface a serialisation failure
    // as a test failure (the intended behaviour here).
    #[allow(clippy::expect_used)]
    pub fn sign_response_b64(
        &self,
        name_id: &str,
        audience: &str,
        acs_url: &str,
        in_response_to: &str,
        attributes: &[(&str, &str)],
    ) -> String {
        let response = self.sign_response(name_id, audience, acs_url, in_response_to, attributes);
        let xml = response.to_string().expect("response to_string");
        BASE64_STANDARD.encode(xml.as_bytes())
    }
}

/// Render a DER-encoded X.509 certificate as a PEM-formatted string.
pub fn der_to_pem(der: &[u8]) -> String {
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

/// Composed test SP. Holds every dep the SAML service requires plus
/// the tracked org / `org_idp` ids for the integration suite to
/// drive.
pub struct TestSp {
    pub service: Arc<SamlService>,
    pub pool: PgPool,
    pub org_id: Uuid,
    pub org_idp_id: Uuid,
    pub orgs: OrgRepo,
    pub idps: OrgIdpRepo,
    pub pending: SamlPendingRepo,
    pub replay: SamlReplayRepo,
    pub federated: FederatedIdentityRepo,
    pub memberships: MembershipRepo,
    pub users: UserRepo,
    pub jit: SamlJitProvisioner,
    pub session_issuer: Arc<IdentitySessionIssuer>,
    pub secrets: Arc<Secrets>,
}

/// Configuration knobs for [`TestSp::seed`].
#[derive(Clone, Debug)]
pub struct SeedOpts {
    pub allow_idp_initiated: bool,
    pub trust_email_assertion: bool,
    pub default_role: String,
}

impl Default for SeedOpts {
    fn default() -> Self {
        Self {
            allow_idp_initiated: false,
            trust_email_assertion: true,
            default_role: "member".to_owned(),
        }
    }
}

impl TestSp {
    /// Wire the SAML service against the supplied PG pool + `IdP`
    /// fixture. Seeds an `orgs` row + a SAML `org_idps` row using
    /// `idp.entity_id` as the pinned `IdP` entity id.
    // test fixture: `expect` panics surface a DB-seed failure as a
    // test failure (the intended behaviour here).
    #[allow(clippy::expect_used)]
    pub async fn seed(pool: PgPool, idp: &TestIdp, opts: SeedOpts) -> Self {
        let secrets = Arc::new(Secrets::from_key(Box::new([0x42; 32])));

        // Seed orgs + org_idps row.
        let org_id = super::seed_org(&pool, TEST_ORG_SLUG)
            .await
            .expect("seed org");
        let org_idp_repo = OrgIdpRepo::new(pool.clone());
        let cfg = SamlConfigV1 {
            config_version: 1,
            idp_entity_id: idp.entity_id.clone(),
            idp_sso_url: format!("{}/SSOService.php", idp.entity_id.trim_end_matches('/')),
            idp_x509_cert_pem: idp.cert_pem.clone(),
            allow_idp_initiated: opts.allow_idp_initiated,
            trust_email_assertion: opts.trust_email_assertion,
            default_role: opts.default_role,
            attribute_mapping: AttributeMapping::default(),
            sp_signing_key: None as Option<EncryptedKey>,
            sp_signing_alg: SpSigningAlg::default(),
            sp_signing_cert_pem: None,
        };
        let scoped = OrgScoped::new(&org_idp_repo, org_id);
        let org_idp = scoped
            .create(NewOrgIdp {
                id: Uuid::now_v7(),
                protocol: "saml",
                display_name: "Test SAML",
                config: serde_json::to_value(&cfg).expect("serialize"),
                config_version: 1,
                jit_provisioning: opts.trust_email_assertion,
                is_default: true,
                enabled: true,
            })
            .await
            .expect("seed org_idp");

        // Compose deps.
        let orgs = OrgRepo::new(pool.clone());
        let idps = org_idp_repo;
        let pending = SamlPendingRepo::new(pool.clone());
        let replay = SamlReplayRepo::new(pool.clone());
        let federated = FederatedIdentityRepo::new(pool.clone());
        let memberships = MembershipRepo::new(pool.clone());
        let users = UserRepo::new(pool.clone());
        let sessions = SessionRepo::new(pool.clone());
        let jit = SamlJitProvisioner::new(users.clone(), federated.clone(), memberships.clone());

        let session_config = Arc::new(test_identity_config());
        let session_issuer = Arc::new(IdentitySessionIssuer::new(session_config, sessions));

        let acs_deps = AcsDeps {
            orgs: orgs.clone(),
            idps: idps.clone(),
            pending: pending.clone(),
            replay: replay.clone(),
            users: users.clone(),
            federated: federated.clone(),
            memberships: memberships.clone(),
            jit: jit.clone(),
            session_issuer: session_issuer.clone(),
            secrets: secrets.clone(),
            base_url: Arc::from(TEST_BASE_URL),
            pool: pool.clone(),
        };
        let authn_deps = AuthnDeps {
            orgs: orgs.clone(),
            idps: idps.clone(),
            pending: pending.clone(),
            base_url: Arc::from(TEST_BASE_URL),
        };
        let metadata_deps = MetadataDeps {
            orgs: orgs.clone(),
            idps: idps.clone(),
            secrets: secrets.clone(),
            base_url: Arc::from(TEST_BASE_URL),
        };

        let service = Arc::new(SamlService::new(SamlServiceDeps {
            authn: authn_deps,
            acs: acs_deps,
            metadata: metadata_deps,
        }));

        Self {
            service,
            pool,
            org_id,
            org_idp_id: org_idp.id,
            orgs,
            idps,
            pending,
            replay,
            federated,
            memberships,
            users,
            jit,
            session_issuer,
            secrets,
        }
    }

    /// Return the canonical ACS URL the SP advertises in metadata.
    // test API: kept as a `&self` method for call-site ergonomics
    // across the integration suite (`sp.acs_url()`).
    #[allow(clippy::unused_self)]
    pub fn acs_url(&self) -> String {
        format!("{TEST_BASE_URL}/v1/auth/saml/{TEST_ORG_SLUG}/acs")
    }

    /// Return the canonical SP entity id.
    // test API: kept as a `&self` method for call-site ergonomics
    // across the integration suite (`sp.entity_id()`).
    #[allow(clippy::unused_self)]
    pub fn entity_id(&self) -> String {
        format!("{TEST_BASE_URL}/v1/auth/saml/metadata")
    }
}

/// Build a minimal in-memory [`IdentityConfig`] suitable for the
/// session issuer. The default carries `session.ttl_days = 7` and
/// no NATS broker — sufficient for issuance-only tests.
fn test_identity_config() -> IdentityConfig {
    IdentityConfig::default()
}
