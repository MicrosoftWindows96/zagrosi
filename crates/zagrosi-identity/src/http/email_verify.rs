// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! Email-verification HTTP handlers.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::Result;
use crate::http::{IdentityState, landing};
use crate::service::email_verify::EmailVerifyConfirmRequest;

/// JSON body for `POST /v1/auth/email-verifications/confirm`.
#[derive(Debug, Deserialize)]
pub struct ConfirmBody {
    /// Raw `vrf_*` token.
    pub token: String,
}

/// `POST /v1/auth/email-verifications/confirm` handler.
pub async fn confirm(
    State(state): State<IdentityState>,
    Json(body): Json<ConfirmBody>,
) -> Result<StatusCode> {
    state
        .service
        .email_verify_confirm(EmailVerifyConfirmRequest {
            raw_token: body.token,
            correlation_id: Uuid::now_v7(),
        })
        .await?;
    Ok(StatusCode::OK)
}

/// Query string for `GET /v1/auth/email-verifications/landing`.
#[derive(Debug, Deserialize)]
pub struct LandingQuery {
    /// Raw `vrf_*` token.
    pub token: String,
}

/// `GET /v1/auth/email-verifications/landing` handler.
pub async fn landing(Query(q): Query<LandingQuery>) -> Response {
    landing::render_landing("/v1/auth/email-verifications/confirm", &q.token)
}
