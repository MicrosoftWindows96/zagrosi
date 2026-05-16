// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Sign-up / sign-in / sign-out HTTP handlers.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use zagrosi_core::AuthContext;

use crate::error::{IdentityError, Result};
use crate::http::IdentityState;
use crate::service::signin::SignInRequest;
use crate::service::signup::{SignUpRequest, SignUpResponse};
use crate::session::{
    IssuedSession, SessionAttachment, build_clear_csrf_cookie, build_clear_session_cookie,
    generate_csrf_value,
};

/// JSON body for `POST /v1/auth/sign-up`.
#[derive(Debug, serde::Deserialize)]
pub struct SignUpBody {
    /// Display-case email submitted by the caller.
    pub email: String,
    /// Display name for the new user.
    pub display_name: String,
    /// Cleartext password.
    pub password: String,
}

/// `POST /v1/auth/sign-up` handler.
pub async fn sign_up(
    State(state): State<IdentityState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<SignUpBody>,
) -> Result<(StatusCode, Json<SignUpResponse>)> {
    let response = state
        .service
        .sign_up(SignUpRequest {
            email: body.email,
            display_name: body.display_name,
            password: body.password,
            ip: addr.ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

/// JSON body for `POST /v1/auth/sign-in`.
#[derive(Debug, serde::Deserialize)]
pub struct SignInBody {
    /// Display-case email submitted by the caller.
    pub email: String,
    /// Cleartext password.
    pub password: String,
}

/// JSON response for `POST /v1/auth/sign-in`.
#[derive(Debug, serde::Serialize)]
pub struct SignInResponse {
    /// Always `"ok"`.
    pub status: &'static str,
    /// Issued session id (for client-side telemetry; cookie is what
    /// authorises subsequent requests).
    pub session_id: Uuid,
    /// Issued session metadata.
    pub session: SignInSession,
    /// Raw `sid_*` credential for non-browser clients that use bearer
    /// authentication instead of the emitted session cookie.
    pub session_token: String,
    /// CSRF double-submit value emitted both in the response body and
    /// the readable CSRF cookie.
    pub csrf_token: String,
}

/// Session metadata returned after password sign-in.
#[derive(Debug, serde::Serialize)]
pub struct SignInSession {
    /// Session row identifier.
    pub id: Uuid,
    /// Owning user.
    pub user_id: Uuid,
    /// Active organisation selected at issue time, when known.
    pub org_id: Option<Uuid>,
    /// Hard expiry timestamp for the issued session.
    pub expires_at: DateTime<Utc>,
}

impl From<&IssuedSession> for SignInSession {
    fn from(session: &IssuedSession) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id,
            org_id: session.org_id,
            expires_at: session.expires_at,
        }
    }
}

/// `POST /v1/auth/sign-in` handler.
pub async fn sign_in(
    State(state): State<IdentityState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<SignInBody>,
) -> Result<Response> {
    let session = state
        .service
        .sign_in(SignInRequest {
            email: body.email,
            password: body.password,
            ip: addr.ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    let attachment = SessionAttachment::new(session.raw_token.clone(), generate_csrf_value());
    let mut headers = HeaderMap::new();
    append_set_cookie(&mut headers, &attachment.session_set_cookie())?;
    append_set_cookie(&mut headers, &attachment.csrf_set_cookie())?;
    Ok((
        StatusCode::OK,
        headers,
        Json(SignInResponse {
            status: "ok",
            session_id: session.id,
            session: SignInSession::from(&session),
            session_token: attachment.raw_session_token,
            csrf_token: attachment.csrf_value,
        }),
    )
        .into_response())
}

/// `POST /v1/auth/sign-out` handler.
pub async fn sign_out(
    State(state): State<IdentityState>,
    ctx: Option<Extension<AuthContext>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> Result<Response> {
    let Some(Extension(ctx)) = ctx else {
        return Err(IdentityError::InvalidCredentials);
    };
    state
        .service
        .sign_out(
            ctx.session_id(),
            Some(ctx.subject_id()),
            Some(addr.ip()),
            Uuid::now_v7(),
        )
        .await?;
    let mut headers = HeaderMap::new();
    append_set_cookie(&mut headers, &build_clear_session_cookie())?;
    append_set_cookie(&mut headers, &build_clear_csrf_cookie())?;
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

fn append_set_cookie(headers: &mut HeaderMap, value: &str) -> Result<()> {
    let header_value =
        HeaderValue::from_str(value).map_err(|_| IdentityError::ResponseHeaderMalformed {
            reason: "set-cookie header value contains illegal byte".into(),
        })?;
    headers.append(header::SET_COOKIE, header_value);
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn sign_in_response_surfaces_session_credential_material() {
        let issued = IssuedSession {
            id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
            org_id: Some(Uuid::now_v7()),
            expires_at: Utc::now(),
            raw_token: "sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        };
        let attachment = SessionAttachment::new(issued.raw_token.clone(), "c".repeat(43));
        let response = SignInResponse {
            status: "ok",
            session_id: issued.id,
            session: SignInSession::from(&issued),
            session_token: attachment.raw_session_token,
            csrf_token: attachment.csrf_value,
        };

        assert_eq!(response.session_id, issued.id);
        assert_eq!(
            response.session_token,
            "sid_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(response.csrf_token, "c".repeat(43));
        assert_eq!(response.session.user_id, issued.user_id);
    }

    #[test]
    fn appends_multiple_set_cookie_headers() {
        let mut headers = HeaderMap::new();
        append_set_cookie(&mut headers, "a=b").expect("first cookie is valid");
        append_set_cookie(&mut headers, "c=d").expect("second cookie is valid");

        assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 2);
    }
}
