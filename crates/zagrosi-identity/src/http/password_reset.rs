// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Password-reset HTTP handlers.

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::Result;
use crate::http::{IdentityState, landing};
use crate::service::password_reset::{PasswordResetConfirmRequest, PasswordResetRequestRequest};

/// JSON body for `POST /v1/auth/password-reset/request`.
#[derive(Debug, Deserialize)]
pub struct ResetRequestBody {
    /// Email address to issue the reset token to.
    pub email: String,
}

/// `POST /v1/auth/password-reset/request` handler.
pub async fn request(
    State(state): State<IdentityState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<ResetRequestBody>,
) -> Result<StatusCode> {
    state
        .service
        .password_reset_request(PasswordResetRequestRequest {
            email: body.email,
            ip: addr.ip(),
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    Ok(StatusCode::OK)
}

/// JSON body for `POST /v1/auth/password-reset/confirm`.
#[derive(Debug, Deserialize)]
pub struct ResetConfirmBody {
    /// Raw `rst_*` token.
    pub token: String,
    /// New cleartext password.
    pub new_password: String,
}

/// `POST /v1/auth/password-reset/confirm` handler.
pub async fn confirm(
    State(state): State<IdentityState>,
    Json(body): Json<ResetConfirmBody>,
) -> Result<StatusCode> {
    state
        .service
        .password_reset_confirm(PasswordResetConfirmRequest {
            raw_token: body.token,
            new_password: body.new_password,
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    Ok(StatusCode::OK)
}

/// Query string for `GET /v1/auth/password-reset/landing`.
#[derive(Debug, Deserialize)]
pub struct LandingQuery {
    /// Raw `rst_*` token.
    pub token: String,
}

/// `GET /v1/auth/password-reset/landing` handler.
pub async fn landing(Query(q): Query<LandingQuery>) -> Response {
    landing::render_landing("/v1/auth/password-reset/confirm", &q.token)
}
