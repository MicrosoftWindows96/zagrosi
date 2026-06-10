// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OidcService` — start + callback orchestrator.
//!
//! Composes [`crate::oidc::config::OidcConfigV1`],
//! [`crate::oidc::cookie::CallbackPayload`],
//! [`crate::oidc::pending::PendingService`],
//! [`crate::oidc::client::OidcClient`],
//! [`crate::oidc::jit::JitProvisioner`],
//! [`crate::oidc::refresh::RefreshChain`], the discovery cache, the
//! session issuer, and the auditor. Two entry points: [`OidcService::start`]
//! and [`OidcService::callback`].
//!
//! Every callback failure path runs through a single audit-emission
//! wrapper so the section-10 contract "every error path emits exactly
//! one `signin_failed` (or more specific) audit event" cannot regress
//! by adding a new `?` operator. Audit events are awaited inline so
//! they survive process drain (`SIGTERM`, blue/green rollover); the
//! port's documented "best-effort; failure must not propagate" still
//! applies but at the auditor implementation level, not at the call
//! site.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::Utc;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient};
use openidconnect::{
    ClientId, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use url::Url;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, Auditor,
};
use zeroize::Zeroizing;

use crate::crypto::Secrets;
use crate::error::{IdentityError, Result};
use crate::oidc::client::{OidcClient, VerifiedIdToken};
use crate::oidc::config::OidcConfigV1;
use crate::oidc::cookie::{self, COOKIE_NAME, CallbackPayload};
use crate::oidc::discovery::DiscoveryCache;
use crate::oidc::jit::{JitInput, JitOutcome, JitProvisioner};
use crate::oidc::pending::{DEFAULT_PENDING_TTL, PendingService, StartContext};
use crate::oidc::refresh::RefreshChain;
use crate::repo::{MembershipRepo, OrgIdpRepo, OrgRepo, OrgScoped, UserRepo, with_org_context};
use crate::session::{IdentitySessionIssuer, SessionAttachment};

/// Outcome of [`OidcService::start`].
#[derive(Debug)]
pub struct StartOutcome {
    /// IdP authorization URL the caller redirects the browser to.
    pub redirect_url: Url,
    /// `Set-Cookie` header value to attach (`__Host-zagrosi_oidc=...`).
    pub set_cookie_value: String,
}

/// Outcome of [`OidcService::callback`].
#[derive(Debug)]
pub struct CallbackOutcome {
    /// Resolved user id (existing user or freshly JIT-provisioned).
    pub user_id: Uuid,
    /// Active org id stamped on the session.
    pub org_id: Uuid,
    /// Session attachment carrying the issued session cookie pair
    /// (`__Host-zagrosi_sid` + `__Host-zagrosi_csrf`).
    pub attachment: SessionAttachment,
    /// `Set-Cookie` clear value for the OIDC cookie. The HTTP handler
    /// stamps this on every response (success and failure).
    pub clear_oidc_cookie: String,
    /// Where to redirect the browser after success. Defaults to `/`.
    pub redirect_to: String,
}

/// Composed OIDC orchestrator. Cheap to clone (every dep is an `Arc`
/// or a repo handle).
#[derive(Clone)]
pub struct OidcService {
    discovery: Arc<DiscoveryCache>,
    pending: PendingService,
    org_repo: OrgRepo,
    idp_repo: OrgIdpRepo,
    jit: JitProvisioner,
    user_repo: UserRepo,
    membership_repo: MembershipRepo,
    client: OidcClient,
    refresh: RefreshChain,
    session_issuer: Arc<IdentitySessionIssuer>,
    auditor: Arc<dyn Auditor>,
    secrets: Arc<Secrets>,
    base_url: String,
    pool: sqlx::PgPool,
    pending_ttl_seconds: u32,
}

/// Build-args bundle for [`OidcService::new`]. Keeps the constructor
/// readable as the dep list grows.
pub struct OidcServiceDeps {
    /// Shared per-issuer discovery cache.
    pub discovery: Arc<DiscoveryCache>,
    /// Pending-row façade.
    pub pending: PendingService,
    /// Org lookup (start handler resolves slug → `org_id`).
    pub org_repo: OrgRepo,
    /// `org_idps` lookup (start handler resolves the IdP for the org).
    pub idp_repo: OrgIdpRepo,
    /// JIT provisioner (callback handler invokes this when the SSO
    /// anchor misses).
    pub jit: JitProvisioner,
    /// User lookup (anchor-hit path verifies the linked user is live).
    pub user_repo: UserRepo,
    /// Membership lookup (anchor-hit path verifies a live membership in
    /// the resolved callback org).
    pub membership_repo: MembershipRepo,
    /// Strongly-typed `openidconnect` wrapper.
    pub client: OidcClient,
    /// Refresh-token chain orchestrator.
    pub refresh: RefreshChain,
    /// Concrete session issuer (the OIDC callback uses `acr` + `amr`).
    pub session_issuer: Arc<IdentitySessionIssuer>,
    /// Audit-event sink.
    pub auditor: Arc<dyn Auditor>,
    /// Secrets shim used to seal/open the OIDC cookie + the
    /// `client_secret_ref` envelope.
    pub secrets: Arc<Secrets>,
    /// Public base URL (`ZAGROSI_BASE_URL`); the callback `redirect_uri`
    /// derives from this when the per-IdP override is `None`.
    pub base_url: String,
    /// Connection pool — the callback handler opens the JIT + session
    /// transaction here.
    pub pool: sqlx::PgPool,
    /// Pending-row TTL in seconds (default 600 = 10 minutes). Mirrors
    /// [`crate::oidc::pending::DEFAULT_PENDING_TTL`].
    pub pending_ttl_seconds: u32,
}

/// Internal carrier between [`OidcService::callback_inner`] and the
/// outer audit + cookie-clear wrapper.
struct InnerSuccess {
    user_id: Uuid,
    session_id: Uuid,
    attachment: SessionAttachment,
    org_idp_id: Uuid,
}

impl OidcService {
    /// Wire dependencies. The default `pending_ttl_seconds` is
    /// 10 minutes; callers MAY shrink it on regulated deployments.
    #[must_use]
    pub fn new(deps: OidcServiceDeps) -> Self {
        Self {
            discovery: deps.discovery,
            pending: deps.pending,
            org_repo: deps.org_repo,
            idp_repo: deps.idp_repo,
            jit: deps.jit,
            user_repo: deps.user_repo,
            membership_repo: deps.membership_repo,
            client: deps.client,
            refresh: deps.refresh,
            session_issuer: deps.session_issuer,
            auditor: deps.auditor,
            secrets: deps.secrets,
            base_url: deps.base_url,
            pool: deps.pool,
            pending_ttl_seconds: deps.pending_ttl_seconds,
        }
    }

    /// Start an OIDC sign-in flow. Resolves the org, picks the IdP,
    /// mints a fresh CSRF / nonce / PKCE verifier, persists a pending
    /// row carrying only the hashes, and returns the IdP authorization
    /// URL plus the sealed cookie value.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OrgNotFound`] when the slug does not resolve
    ///   to a live org.
    /// - [`IdentityError::OidcIdpNotFound`] when no enabled OIDC IdP
    ///   exists for the resolved org.
    /// - [`IdentityError::OidcAmbiguousIdp`] when multiple enabled
    ///   OIDC IdPs exist and the caller did not narrow the choice.
    /// - [`IdentityError::OidcConfigInvalid`] when the IdP's stored
    ///   config fails revalidation.
    /// - [`IdentityError::OidcDiscoveryFailed`] when the discovery
    ///   pre-warm fails.
    #[tracing::instrument(
        skip_all,
        fields(
            org_slug = %org_slug,
            route = "oidc.start",
        )
    )]
    pub async fn start(&self, org_slug: &str) -> Result<StartOutcome> {
        let org = self
            .org_repo
            .find_by_slug(org_slug)
            .await?
            .ok_or(IdentityError::OrgNotFound)?;

        let scoped = OrgScoped::new(&self.idp_repo, org.id);
        let mut oidc_idps: Vec<_> = scoped
            .list_for_org()
            .await?
            .into_iter()
            .filter(|idp| idp.enabled && idp.protocol == "oidc")
            .collect();
        if oidc_idps.is_empty() {
            return Err(IdentityError::OidcIdpNotFound);
        }
        if oidc_idps.len() > 1 {
            // v0.1: section-13's multi-IdP routing layer narrows by
            // `?domain=`. The OIDC service rejects ambiguous calls
            // until that lands.
            return Err(IdentityError::OidcAmbiguousIdp);
        }
        let idp = oidc_idps.remove(0);

        let cfg = OidcConfigV1::from_jsonb(&idp.config)?;
        let snapshot = self.discovery.get(&cfg.issuer_url).await?;

        let payload = CallbackPayload::new_random();
        let state = CsrfToken::new_random();
        // Lift the raw OAuth `state` value into `Zeroizing<String>`
        // so the heap buffer scrubs on drop. The `state` lives on the
        // stack across the pending-insert + cookie-seal awaits; without
        // the wrapper, plaintext would linger until allocator reuse.
        // Mirrors the saml issuer's `Zeroizing<String>` pattern over
        // the raw session token + CSRF value.
        let state_str: Zeroizing<String> = Zeroizing::new(state.secret().clone());
        let redirect_uri = self.derive_redirect_uri(org_slug, cfg.redirect_uri_override.as_ref());

        // `authorize_url` needs only the client_id + redirect_uri; the
        // client_secret is not part of the front-channel request, so we
        // skip secret unsealing here. The token-exchange path (callback)
        // is the only place that touches the secret.
        //
        // openidconnect 4.x type-states `EndpointSet`/`EndpointMaybeSet`
        // through the builder chain; we keep the client value-typed and
        // build it inline so the generic params resolve to the
        // post-`set_redirect_uri` shape that `authorize_url` requires.
        let metadata = snapshot.metadata.clone();
        let client_id = ClientId::new(cfg.client_id.clone());
        let redirect = RedirectUrl::new(redirect_uri.clone()).map_err(|err| {
            IdentityError::OidcConfigInvalid {
                reason: format!("redirect_uri malformed: {err}"),
            }
        })?;
        let core_client = CoreClient::from_provider_metadata(metadata, client_id, None)
            .set_redirect_uri(redirect);

        let verifier_obj = PkceCodeVerifier::new(payload.verifier.clone());
        let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier_obj);
        let nonce_obj = Nonce::new(payload.nonce.clone());
        let state_clone = state.clone();
        let nonce_clone = nonce_obj;

        let mut auth_flow = core_client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            move || state_clone,
            move || nonce_clone,
        );
        for scope in &cfg.scopes {
            auth_flow = auth_flow.add_scope(Scope::new(scope.clone()));
        }
        if cfg.enable_refresh && !cfg.scopes.iter().any(|s| s == "offline_access") {
            auth_flow = auth_flow.add_scope(Scope::new("offline_access".into()));
        }
        let (auth_url, _state_again, _nonce_again) = auth_flow.set_pkce_challenge(challenge).url();

        self.pending
            .insert_for_start(StartContext {
                org_idp_id: idp.id,
                redirect_uri: &redirect_uri,
                state: state_str.as_str(),
                cookie_payload: &payload,
                expires_at: Some(Utc::now() + DEFAULT_PENDING_TTL),
            })
            .await?;

        let set_cookie =
            cookie::build_set_cookie_header(&self.secrets, &payload, self.pending_ttl_seconds)?;

        Ok(StartOutcome {
            redirect_url: auth_url,
            set_cookie_value: set_cookie,
        })
    }

    /// Process a callback. Runs the section-10 callback protocol and
    /// emits exactly one audit event per outcome (success or failure).
    ///
    /// Every error returned from this method has already been recorded
    /// through `Self::audit_failure`; HTTP handlers do not need to
    /// re-emit. The clear-OIDC-cookie header is included on the
    /// success outcome and on the [`CallbackOutcome::clear_oidc_cookie`]
    /// the wrapper builds for the failure path through
    /// [`build_clear_cookie`].
    #[tracing::instrument(
        skip_all,
        fields(
            org_id = %input.expected_org_id,
            correlation_id = %input.correlation_id,
            route = "oidc.callback",
        )
    )]
    pub async fn callback(&self, input: CallbackInput<'_>) -> Result<CallbackOutcome> {
        match self.callback_inner(input).await {
            Ok(InnerSuccess {
                user_id,
                session_id,
                attachment,
                org_idp_id,
            }) => {
                self.audit_success(input, user_id, session_id, org_idp_id)
                    .await;
                Ok(CallbackOutcome {
                    user_id,
                    org_id: input.expected_org_id,
                    attachment,
                    clear_oidc_cookie: build_clear_cookie(),
                    redirect_to: "/".to_owned(),
                })
            }
            Err(err) => {
                self.audit_failure(input, &err).await;
                Err(err)
            }
        }
    }

    /// Inner callback flow. Failures propagate untyped — the outer
    /// `callback` wrapper is the single audit-emission point.
    #[allow(clippy::too_many_lines)]
    async fn callback_inner(&self, input: CallbackInput<'_>) -> Result<InnerSuccess> {
        // Step 0: open + authenticate the cookie envelope. Crypto-layer
        // failures (AEAD tag mismatch, wrong key id, malformed
        // envelope) are normalised to the OIDC family so the
        // taxonomic mapping in `IdentityError::into_response` returns
        // the uniform `oidc_callback_failed` envelope rather than
        // `500 internal_error`.
        let cookie = self
            .open_cookie(input.cookie_value)
            .map_err(normalise_cookie_open_error)?;

        // Step 1+2: lookup pending row + constant-time hash compare.
        // The pending repo no longer filters `used_at IS NULL`, so a
        // deliberate replay surfaces as `OidcReplay` rather than
        // collapsing into the generic state-mismatch family.
        let pending = self.pending.resolve_callback(input.state, &cookie).await?;

        // Step 3: re-load the IdP under the org_id resolved from the
        // slug. Cross-org callback forgery surfaces as `None` (because
        // the `OrgScoped` predicate hard-anchors `WHERE org_id = $1`)
        // and we collapse it onto the same uniform state-mismatch
        // family.
        let scoped = OrgScoped::new(&self.idp_repo, input.expected_org_id);
        let idp = scoped
            .find_by_id(pending.org_idp_id)
            .await?
            .ok_or(IdentityError::OidcStateMismatch)?;
        let cfg = OidcConfigV1::from_jsonb(&idp.config)?;

        // Step 4: defensive verbatim compare of the redirect URI on the
        // pending row vs. the current request's expected callback path.
        // The pending row was stamped at `start` time; if the current
        // request's path does not match, a forged callback is in
        // flight.
        let expected_redirect = self.derive_redirect_uri(
            input
                .expected_org_slug
                .ok_or(IdentityError::OidcStateMismatch)?,
            cfg.redirect_uri_override.as_ref(),
        );
        let same_redirect: bool = expected_redirect
            .as_bytes()
            .ct_eq(pending.redirect_uri.as_bytes())
            .into();
        if !same_redirect {
            return Err(IdentityError::OidcStateMismatch);
        }

        // Step 5: RFC 9207 `iss` mix-up defence. Trim the canonical
        // trailing slash on both sides so `https://idp/` and
        // `https://idp` compare equal — IdPs normalise differently
        // (Authentik, Keycloak, Okta).
        if let Some(iss_query) = input.iss_query
            && !iss_query.is_empty()
        {
            let pinned = cfg.issuer_url.as_str().trim_end_matches('/');
            let observed = iss_query.trim_end_matches('/');
            let same: bool = observed.as_bytes().ct_eq(pinned.as_bytes()).into();
            if !same {
                return Err(IdentityError::OidcIssMismatch);
            }
        }

        // Step 6: code exchange + ID-token validation. The OIDC client
        // re-fetches discovery + JWKS through the cache, runs the
        // claim chain (iss / aud / azp / exp / iat / nonce / at_hash /
        // c_hash), and pins the JWKS thumbprint when configured.
        let snapshot = self.discovery.get(&cfg.issuer_url).await?;
        let client_secret = cfg.client_secret(&self.secrets)?;
        let redirect_uri = pending.redirect_uri.clone();

        let verified = self
            .client
            .exchange_and_verify(
                &snapshot,
                &cfg,
                client_secret,
                &redirect_uri,
                &cookie.nonce,
                &cookie.verifier,
                input.code,
                Some(self.discovery.as_ref()),
            )
            .await?;

        // Step 7: SSO anchor lookup. The anchor key is the verified
        // ID-token claim's `iss` + `sub` (NOT the config issuer);
        // canonicalise by trimming the trailing slash so successive
        // sign-ins from the same IdP land on the same anchor row even
        // when the config URL and the claim disagree on the slash.
        let issuer_str = verified
            .claims
            .issuer()
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let subject_str = verified.claims.subject().as_str().to_owned();

        let mut tx = self.pool.begin().await?;
        with_org_context(&mut tx, input.expected_org_id).await?;

        // Anchor lookup runs inside the tx so a tombstone-flip racing
        // the in-flight transaction is observed against a single
        // consistency horizon.
        let federated_lookup = self
            .jit
            .federated_lookup_in_tx(&mut tx, &issuer_str, &subject_str)
            .await?;

        let (user_id, anchor_id) = if let Some(existing) = federated_lookup {
            // Cross-tenant defence FIRST: an anchor that does not
            // belong to this callback's IdP collapses to the uniform
            // state-mismatch family, regardless of tombstone state.
            // Order matters: a tombstoned anchor for a DIFFERENT IdP
            // would otherwise return `account_disabled` (409) and
            // become a cross-tenant existence oracle.
            if existing.org_idp_id != idp.id {
                return Err(IdentityError::OidcStateMismatch);
            }

            // Tombstoned anchor (legitimate IdP, tombstoned by admin).
            // Surface as `account_disabled` rather than the
            // tombstone-specific 409 so the public envelope stays
            // uniform with the rest of the OIDC failure family.
            let Some(uid) = existing.user_id else {
                return Err(IdentityError::AccountDisabled);
            };

            // The linked user must still be live. Read inside the
            // tx so the consistency horizon matches the pending
            // mark-used + JIT writes the callback is about to commit.
            self.user_repo
                .find_by_id_in_tx(&mut tx, uid)
                .await?
                .ok_or(IdentityError::AccountDisabled)?;

            // The user must have a live membership in the org the slug
            // resolved to. Without this gate, an anchor minted under
            // org A could mint a session for org B that happens to
            // share the IdP.
            self.membership_repo
                .find_for_user_org_in_tx(&mut tx, uid, input.expected_org_id)
                .await?
                .ok_or(IdentityError::OidcStateMismatch)?;

            (uid, existing.id)
        } else {
            // JIT path - require the per-IdP toggle to be enabled.
            // Audit family is `signin_failed` (admin-policy denial,
            // not state forgery).
            if !idp.jit_provisioning {
                return Err(IdentityError::OidcJitDisabled);
            }

            let email_value = verified
                .claims
                .email()
                .map(|e| e.as_str().to_owned())
                .ok_or(IdentityError::OidcIdTokenInvalid("missing email claim"))?;
            // SQL canonicalises both sides via `lower($1)` in
            // `UserRepo::find_by_email_lower_in_tx`, and the DB-side
            // `users.email_lower` is a generated column populated by
            // `lower(email)` on insert. Pass the display-case value
            // through verbatim so both compare arms run through the
            // same locale-aware Postgres `lower()` and a Turkish
            // dotless-i / German ß / Cyrillic mismatch with Rust's
            // `to_lowercase` cannot drift.
            let email_lower_value = email_value.clone();
            let display_name_value = verified
                .claims
                .name()
                .and_then(|name| name.iter().next())
                .map_or_else(
                    || derive_display_name_fallback(&verified),
                    |(_, ln)| ln.as_str().to_owned(),
                );

            let JitOutcome { user, anchor } = self
                .jit
                .run(
                    &mut tx,
                    JitInput {
                        org_id: input.expected_org_id,
                        org_idp_id: idp.id,
                        issuer: issuer_str.clone(),
                        subject: subject_str.clone(),
                        email: email_value,
                        email_lower: email_lower_value,
                        display_name: display_name_value,
                        email_verified: verified.claims.email_verified().unwrap_or(false),
                        allow_unverified: cfg.allow_unverified_email_jit,
                        default_role: cfg
                            .default_role
                            .clone()
                            .unwrap_or_else(|| "member".to_owned()),
                    },
                    Utc::now(),
                )
                .await?;
            (user.id, anchor.id)
        };

        // Step 8: mark the pending row used. The `WHERE used_at IS
        // NULL` predicate gives us atomic single-use semantics; if a
        // concurrent callback already consumed the row, mark_used
        // returns `OidcReplay`.
        self.pending.mark_used(&mut tx, pending.id).await?;

        // Step 9: bump `last_login_at` inside the same transaction so
        // a tx rollback never leaves a phantom-success timestamp on
        // the anchor.
        self.jit
            .federated_update_last_login_in_tx(&mut tx, anchor_id, Utc::now())
            .await?;

        // Step 10: issue the fresh session inside the same tx. The
        // `acr` / `amr` claims are extracted via the side-channel JWT
        // body parse in `client.rs`.
        //
        // Issuing the session BEFORE `tx.commit()` is required for
        // atomicity: a session-row insert failure on the post-commit
        // path used to leave a JIT-provisioned user with a consumed
        // pending row + bumped `last_login_at` but no session, locking
        // that user out for the callback. With the in-tx variant the
        // entire callback payload commits or rolls back as a single
        // unit. Mirrors `saml::acs::handler` step M.
        let amr_owned: Vec<String> = verified.acr_amr.amr.clone().unwrap_or_default();
        let amr_refs: Vec<&str> = amr_owned.iter().map(String::as_str).collect();
        let acr_str = verified.acr_amr.acr.as_deref();
        let (issued, attachment) = self
            .session_issuer
            .issue_with_attachment_in_tx(
                &mut tx,
                user_id,
                Some(input.expected_org_id),
                amr_refs.as_slice(),
                acr_str,
            )
            .await?;

        tx.commit().await?;

        // Step 11: seed the refresh chain when the IdP returned a
        // refresh token AND the per-IdP `enable_refresh` toggle is on.
        // Some IdPs return a refresh token even when `offline_access`
        // was not requested (Okta's "automatic refresh" path);
        // persisting it under `enable_refresh = false` would let the
        // gateway's rotation handler use a credential the admin had
        // explicitly disabled. The raw refresh token is dropped on
        // scope exit when this branch does not run.
        //
        // Refresh-seed runs POST-commit because it FK-references
        // `sessions.id` — the session row must already be visible for
        // the seed insert to succeed. A seed-failure post-commit leaves
        // an orphan session (usable today, must re-auth when the
        // access-token TTL elapses); strictly weaker than the
        // pre-fix lockout window (no session at all).
        if cfg.enable_refresh
            && let Some(refresh_token) = verified.refresh_token.as_ref()
        {
            self.refresh
                .issue_initial(issued.id, refresh_token.expose_secret())
                .await?;
        }

        Ok(InnerSuccess {
            user_id,
            session_id: issued.id,
            attachment,
            org_idp_id: idp.id,
        })
    }

    fn open_cookie(&self, cookie_value: Option<&str>) -> Result<CallbackPayload> {
        let raw = cookie_value.ok_or(IdentityError::OidcCookieMissing)?;
        cookie::open(&self.secrets, raw)
    }

    fn derive_redirect_uri(&self, org_slug: &str, override_uri: Option<&Url>) -> String {
        if let Some(o) = override_uri {
            return o.to_string();
        }
        let trimmed = self.base_url.trim_end_matches('/');
        format!("{trimmed}/v1/auth/oidc/{org_slug}/callback")
    }

    /// Emit the success audit event. Awaited inline so the auditor
    /// runs in the request future and dies with it; the auditor port
    /// already documents that record is best-effort.
    async fn audit_success(
        &self,
        input: CallbackInput<'_>,
        user_id: Uuid,
        session_id: Uuid,
        org_idp_id: Uuid,
    ) {
        let event = AuditEvent::V1(
            AuditEventV1::builder(
                AuditEventKind::SigninSuccess,
                AuditActor::User {
                    user_id,
                    ip: input.client_ip,
                },
                Some(input.expected_org_id),
                input.correlation_id,
            )
            .resource(AuditResource::Session { session_id })
            .metadata(AuditPayload::new(serde_json::json!({
                "auth_method": "oidc",
                "user_id": user_id,
                "org_idp_id": org_idp_id,
            })))
            .build(),
        );
        self.auditor.record(event).await;
    }

    /// Emit a failure audit event from outside `callback_inner` (HTTP
    /// handler short-circuits: org-not-found, IdP-error redirect,
    /// missing-code/state). `org_id` is `None` when the failure precedes
    /// org-slug resolution — org-enumeration probes have no org. The
    /// handler does not own the `Auditor` directly; this surface routes
    /// through the service so the SIEM sees one event-per-failure
    /// regardless of where the short-circuit fired.
    pub async fn audit_handler_failure(
        &self,
        org_id: Option<Uuid>,
        correlation_id: Uuid,
        client_ip: Option<IpAddr>,
        err: &IdentityError,
    ) {
        self.emit_failure_event(org_id, correlation_id, client_ip, err)
            .await;
    }

    /// Emit a single failure audit event for an error that propagated
    /// out of `callback_inner`. Awaited inline so the request future
    /// owns the auditor I/O — the previous spawn-and-forget pattern
    /// dropped events on shutdown and was unbounded under load.
    async fn audit_failure(&self, input: CallbackInput<'_>, err: &IdentityError) {
        self.emit_failure_event(
            Some(input.expected_org_id),
            input.correlation_id,
            input.client_ip,
            err,
        )
        .await;
    }

    /// Shared failure-event body for [`Self::audit_handler_failure`] and
    /// [`Self::audit_failure`].
    async fn emit_failure_event(
        &self,
        org_id: Option<Uuid>,
        correlation_id: Uuid,
        client_ip: Option<IpAddr>,
        err: &IdentityError,
    ) {
        let kind = err.audit_kind_for_state_family();
        let sub_reason = err.audit_sub_reason();
        let event = AuditEvent::V1(
            AuditEventV1::builder(
                kind,
                AuditActor::Anonymous { ip: client_ip },
                org_id,
                correlation_id,
            )
            .metadata(AuditPayload::new(serde_json::json!({
                "sub_reason": sub_reason,
                "auth_method": "oidc",
            })))
            .build(),
        );
        self.auditor.record(event).await;
    }

    /// Borrow the underlying `OrgRepo` so the HTTP handler can resolve
    /// `org_slug -> org_id` without holding a separate clone.
    #[must_use]
    pub const fn org_repo(&self) -> &OrgRepo {
        &self.org_repo
    }
}

/// Build the clear-cookie header the HTTP handler stamps on every
/// callback response (success and failure). Pulled out so the wrapper
/// in `OidcService::callback` and the HTTP error path produce a
/// byte-equivalent header.
#[must_use]
pub fn build_clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// Map the cookie-open error family into the OIDC family. The crypto
/// shim returns `IntegrityError`, `UnknownKeyId`, and
/// `MalformedEnvelope` for tampered / wrong-key / wire-shape failures;
/// each must surface to the caller as a uniform `oidc_callback_failed`
/// rather than `500 internal_error`.
fn normalise_cookie_open_error(err: IdentityError) -> IdentityError {
    match err {
        // Cookie-open already returned the OIDC family - keep verbatim.
        IdentityError::OidcCookieMissing | IdentityError::OidcCookieMalformed(_) => err,
        // AEAD tag failure on the cookie body is a state-mismatch from
        // the attacker's perspective; collapse onto the uniform
        // surface so the audit signal is correct.
        IdentityError::IntegrityError => IdentityError::OidcStateMismatch,
        IdentityError::UnknownKeyId(_) => {
            IdentityError::OidcCookieMalformed("cookie sealed under unknown key id")
        }
        IdentityError::MalformedEnvelope(reason) => IdentityError::OidcCookieMalformed(reason),
        other => other,
    }
}

/// Callback input bundle.
#[derive(Debug, Clone, Copy)]
pub struct CallbackInput<'a> {
    /// Org id resolved from the org slug parameter. The OIDC service
    /// re-loads the IdP under this `org_id` so a forged cross-org
    /// callback is rejected.
    pub expected_org_id: Uuid,
    /// Org slug as it appeared in the URL path. Used to derive the
    /// canonical redirect URI for the verbatim compare against the
    /// pending row's stored redirect URI.
    pub expected_org_slug: Option<&'a str>,
    /// `code` query parameter. The IdP error path supplies an empty
    /// string when the code is absent; the handler short-circuits
    /// before reaching the service in that case.
    pub code: &'a str,
    /// `state` query parameter.
    pub state: &'a str,
    /// Optional `iss` query parameter (RFC 9207).
    pub iss_query: Option<&'a str>,
    /// Sealed `__Host-zagrosi_oidc` cookie value.
    pub cookie_value: Option<&'a str>,
    /// Per-request correlation ID.
    pub correlation_id: Uuid,
    /// Caller IP for audit metadata. Populated by the HTTP handler
    /// from a trusted gateway-set extension.
    pub client_ip: Option<IpAddr>,
}

/// Fall back when the IdP did not supply a `name` claim. The fallback
/// strips the email's local part. Edge case: emails with quoted local
/// parts ("a@b"@example.com) drop the trailing `@example.com`. RFC-quoted
/// locals are vanishingly rare in OIDC contexts; the fallback is a
/// best-effort display name and is overwritten on the user's first
/// profile edit.
fn derive_display_name_fallback(verified: &VerifiedIdToken) -> String {
    verified.claims.email().map_or_else(
        || verified.claims.subject().as_str().to_owned(),
        |e| {
            let s = e.as_str();
            s.split('@').next().unwrap_or(s).to_owned()
        },
    )
}

impl IdentityError {
    /// Classify each error variant to the audit `event_kind` that best
    /// represents the failure family.
    ///
    /// The spec enumerates three OIDC-specific kinds plus the generic
    /// `signin_failed`:
    ///
    /// - `oidc_callback_replay` for the pending-row replay path.
    /// - `oidc_state_mismatch` for cookie / state forgery.
    /// - `signup_email_collision_attempted` for the JIT collision path.
    /// - `signin_failed` for the long-tail (everything else, with a
    ///   `sub_reason` payload field that ops dashboards key on).
    const fn audit_kind_for_state_family(&self) -> AuditEventKind {
        match self {
            Self::OidcReplay => AuditEventKind::OidcCallbackReplay,
            // `OidcStateMismatch` and `OidcCookieMissing` route to the
            // dedicated state-mismatch kind so attack-detection
            // dashboards page on a sustained surge.
            // `OidcCookieMalformed` collapses onto the generic
            // `SigninFailed` family with `sub_reason="cookie_malformed"`
            // so a deploy that ships a bad cookie format does not
            // mis-fire as an attack signal.
            Self::OidcStateMismatch | Self::OidcCookieMissing => AuditEventKind::OidcStateMismatch,
            Self::OidcAccountAlreadyExists => AuditEventKind::SignupEmailCollisionAttempted,
            _ => AuditEventKind::SigninFailed,
        }
    }

    /// Stable `sub_reason` string carried in the audit payload. Ops
    /// dashboards distinguish failure modes via this value while the
    /// public HTTP envelope stays uniform.
    const fn audit_sub_reason(&self) -> &'static str {
        match self {
            Self::OidcCookieMissing => "cookie_missing",
            Self::OidcCookieMalformed(_) => "cookie_malformed",
            Self::OidcStateMismatch => "state_mismatch",
            Self::OidcReplay => "callback_replay",
            Self::OidcExpired => "pending_expired",
            Self::OidcIssMismatch => "iss_mismatch",
            Self::OidcIdTokenInvalid(_) => "id_token_invalid",
            Self::OidcJwksThumbprintMismatch => "jwks_thumbprint_mismatch",
            Self::OidcEmailNotVerified => "email_not_verified",
            Self::OidcAccountAlreadyExists => "email_collision",
            Self::OidcDiscoveryFailed(_) => "discovery_failed",
            Self::OidcConfigInvalid { .. } => "config_invalid",
            Self::OidcJitDisabled => "jit_disabled",
            Self::FederatedIdentityTombstoned => "tombstoned_anchor",
            Self::AccountDisabled => "account_disabled",
            Self::OrgNotFound => "org_not_found",
            Self::Database(_) => "database_error",
            _ => "internal_error",
        }
    }
}

/// `JitProvisioner` exposes the federated_repo + last-login update
/// helpers needed by `OidcService::callback` without leaking the inner
/// repos to the orchestrator.
impl crate::oidc::jit::JitProvisioner {
    /// Look up the SSO anchor by canonical `(iss, sub)`. Returned
    /// `Option<FederatedIdentity>` carries the tombstone too — the
    /// caller MUST inspect `user_id` before minting a session.
    pub async fn federated_lookup(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<crate::domain::FederatedIdentity>> {
        self.federated_repo()
            .find_by_protocol_iss_sub("oidc", issuer, subject)
            .await
    }

    /// In-tx variant of [`Self::federated_lookup`]. The OIDC service
    /// uses this so the anchor lookup races on the same consistency
    /// horizon as the pending mark-used + JIT writes.
    pub async fn federated_lookup_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<crate::domain::FederatedIdentity>> {
        self.federated_repo()
            .find_by_protocol_iss_sub_in_tx(tx, "oidc", issuer, subject)
            .await
    }

    /// Update `last_login_at` inside the caller's transaction so the
    /// bump rides on the same commit as the pending mark-used + JIT
    /// writes.
    pub async fn federated_update_last_login_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        anchor_id: Uuid,
        last_login_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.federated_repo()
            .update_last_login_at_in_tx(tx, anchor_id, last_login_at)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec: `test_pending_row_state_entropy_at_least_128_bits`. The
    /// state token is minted via `openidconnect::CsrfToken::new_random()`
    /// which the lib defines as 128-bit base64url-encoded entropy. A
    /// 1k-draw collision-free assertion is the practical proxy for the
    /// 128-bit floor: the birthday-bound collision probability across
    /// 1000 draws on a 128-bit space is < 2^-100, so any collision in
    /// this loop signals a regression in the lib's entropy source.
    #[test]
    fn state_token_random_is_high_entropy() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1_000 {
            let s = CsrfToken::new_random();
            assert!(
                seen.insert(s.secret().clone()),
                "csrf_token collision under 1k draws",
            );
        }
    }
}
