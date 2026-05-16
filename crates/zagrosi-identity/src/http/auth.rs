// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Sign-up / sign-in / sign-out HTTP handlers.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

use crate::error::Result;
use crate::http::IdentityState;
use crate::service::signin::SignInRequest;
use crate::service::signup::{SignUpRequest, SignUpResponse};

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
}

/// `POST /v1/auth/sign-in` handler.
pub async fn sign_in(
    State(state): State<IdentityState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<SignInBody>,
) -> Result<Json<SignInResponse>> {
    let session = state
        .service
        .sign_in(SignInRequest {
            email: body.email,
            password: body.password,
            ip: addr.ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    Ok(Json(SignInResponse {
        status: "ok",
        session_id: session.id,
    }))
}

/// JSON body for `POST /v1/auth/sign-out`.
#[derive(Debug, serde::Deserialize)]
pub struct SignOutBody {
    /// Session id to revoke.
    pub session_id: Uuid,
}

/// `POST /v1/auth/sign-out` handler.
pub async fn sign_out(
    State(state): State<IdentityState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<SignOutBody>,
) -> Result<StatusCode> {
    let _ip: IpAddr = addr.ip();
    state
        .service
        .sign_out(body.session_id, None, Some(addr.ip()), Uuid::now_v7())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[allow(dead_code)]
fn dummy_into_response_use<T: IntoResponse>(_: T) {}
