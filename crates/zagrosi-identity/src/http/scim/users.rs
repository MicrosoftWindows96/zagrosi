// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM 2.0 `Users` resource HTTP handlers.
//!
//! All five verbs (`GET` list/by-id, `POST`, `PATCH`, `PUT`,
//! `DELETE`) live here. Every multi-tenant SQL query rides through
//! `UserRepo`'s `_in_org` helpers (which join `user_org_memberships`
//! on the bearer's `org_id`) so cross-tenant probing returns
//! `404 not_found` rather than `403 forbidden`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::QueryBuilder;
use uuid::Uuid;

use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, AuditResource, ServiceName,
};

use crate::domain::User;
use crate::repo::{NewMembership, NewUser, user_from_row};

use super::filter::ResourceKind;
use super::translate::{SortDir, push_filter};

use super::etag::{quoted_etag, version_matches};
use super::patch::{PatchOpInput, apply_user_patch_ops, parse_patch_ops};
use super::{
    SCIM_LIST_RESPONSE_SCHEMA, SCIM_MAX_COUNT, SCIM_USER_SCHEMA, ScimAuth, ScimError, ScimState,
    scim_json, scim_json_with_headers,
};

/// SCIM `User` POST/PUT request body.
#[derive(Debug, Deserialize)]
pub struct UserPayload {
    /// SCIM 2.0 schemas array. RFC 7644 mandates the User core
    /// schema; extensions are permitted but unused in v0.1.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// `userName` — case-insensitive unique within an org.
    #[serde(default, rename = "userName")]
    pub user_name: Option<String>,
    /// `displayName`.
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    /// SCIM `name` complex attribute.
    #[serde(default)]
    pub name: Option<NamePayload>,
    /// SCIM `active` boolean. Defaults to `true` per RFC 7643.
    #[serde(default)]
    pub active: Option<bool>,
    /// SCIM `externalId`.
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    /// SCIM `emails` multi-valued attribute. Only the primary email
    /// (or first entry) is honoured in v0.1.
    #[serde(default)]
    pub emails: Vec<EmailPayload>,
    /// Catch-all for unknown attributes — currently ignored to be
    /// tolerant of producer-side schema extensions; future
    /// revisions may surface unknown attributes as
    /// [`ScimError::InvalidValue`].
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// SCIM `User.name` sub-payload.
#[derive(Debug, Deserialize)]
pub struct NamePayload {
    /// SCIM `name.givenName`.
    #[serde(default, rename = "givenName")]
    pub given_name: Option<String>,
    /// SCIM `name.familyName`.
    #[serde(default, rename = "familyName")]
    pub family_name: Option<String>,
    /// SCIM `name.formatted`.
    #[serde(default)]
    pub formatted: Option<String>,
}

/// SCIM `User.emails[]` element.
#[derive(Debug, Deserialize)]
pub struct EmailPayload {
    /// `value`.
    #[serde(default)]
    pub value: Option<String>,
    /// `type`.
    #[serde(default, rename = "type")]
    pub email_type: Option<String>,
    /// `primary`.
    #[serde(default)]
    pub primary: Option<bool>,
}

/// Query string for `GET /scim/v2/Users`.
#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// SCIM `filter` expression (RFC 7644 §3.4.2.2).
    #[serde(default)]
    pub filter: Option<String>,
    /// 1-based start index.
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<i64>,
    /// Page size; capped server-side at 200.
    #[serde(default)]
    pub count: Option<i64>,
    /// `sortBy` attribute name.
    #[serde(default, rename = "sortBy")]
    pub sort_by: Option<String>,
    /// `sortOrder` (`ascending` | `descending`).
    #[serde(default, rename = "sortOrder")]
    pub sort_order: Option<String>,
    /// SCIM `attributes` projection — accepted but unused in v0.1
    /// (the response shape is stable).
    #[serde(default)]
    pub attributes: Option<String>,
}

impl UserPayload {
    fn primary_email(&self) -> Option<&str> {
        if let Some(name) = self.user_name.as_deref() {
            return Some(name);
        }
        self.emails
            .iter()
            .find(|e| e.primary == Some(true))
            .or_else(|| self.emails.first())
            .and_then(|e| e.value.as_deref())
    }

    fn display_name_or(&self, fallback: &str) -> String {
        if let Some(name) = self.display_name.as_deref() {
            return name.to_string();
        }
        if let Some(name) = self.name.as_ref().and_then(|n| n.formatted.as_deref()) {
            return name.to_string();
        }
        fallback.to_string()
    }
}

/// Project a [`User`] into a SCIM 2.0 `User` JSON body.
///
/// `base_url` is prepended to `meta.location` so the response
/// carries an absolute URI when the deployment configures one
/// (RFC 7643 §3.1 SHOULD-recommendation). Empty `base_url`
/// emits a relative path.
#[must_use]
pub fn to_scim_user(user: &User, base_url: &str) -> Value {
    json!({
        "schemas": [SCIM_USER_SCHEMA],
        "id": user.id.to_string(),
        "userName": user.email_lower,
        "displayName": user.display_name,
        "active": user.active,
        "externalId": user.external_id,
        "emails": [
            {
                "value": user.email_lower,
                "type": "work",
                "primary": true
            }
        ],
        "meta": {
            "resourceType": "User",
            "created": user.created_at.to_rfc3339(),
            "lastModified": user.updated_at.to_rfc3339(),
            "version": quoted_etag(user.updated_at, user.row_version),
            "location": user_location(base_url, user.id)
        }
    })
}

/// Build the canonical `meta.location` for a `Users/{id}` URI.
#[must_use]
pub(crate) fn user_location(base_url: &str, id: Uuid) -> String {
    format!("{base_url}/scim/v2/Users/{id}")
}

/// `GET /scim/v2/Users` — list users in the bearer's org.
///
/// Filter, sort, and pagination compose into a single
/// `sqlx::QueryBuilder`-built statement. Attribute names are
/// resolved through the `&'static str` whitelist
/// ([`super::attrs::user_column`] / [`super::attrs::user_sort_column`])
/// so attacker-controlled input cannot reach the SQL parser as a
/// column name. Right-hand-side literals are bound through
/// `push_bind`. The `count(*)` total is computed against the same
/// filter so `totalResults` reflects the filtered population (RFC
/// 7644 §3.4.2).
pub async fn list_users(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Query(q): Query<ListQuery>,
) -> Result<Response, ScimError> {
    let parsed_filter = match q.filter.as_deref() {
        Some(raw) => Some(super::filter::parse(raw)?),
        None => None,
    };
    let sort_col = match q.sort_by.as_deref() {
        Some(name) => Some(super::attrs::user_sort_column(name)?),
        None => None,
    };
    let sort_dir = SortDir::parse(q.sort_order.as_deref());
    let start_index = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(SCIM_MAX_COUNT).clamp(0, SCIM_MAX_COUNT);
    let offset = start_index.saturating_sub(1);

    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(super::ScimError::from)?;

    let mut total_qb: QueryBuilder<'_, sqlx::Postgres> = QueryBuilder::new(
        "SELECT COUNT(*) FROM users \
         JOIN user_org_memberships m ON m.user_id = users.id \
         WHERE m.org_id = ",
    );
    total_qb.push_bind(auth.org_id);
    total_qb.push(" AND users.deleted_at IS NULL AND m.deleted_at IS NULL");
    if let Some(filter) = &parsed_filter {
        total_qb.push(" AND ");
        push_filter(&mut total_qb, ResourceKind::User, filter)?;
    }
    let total: i64 = total_qb
        .build_query_scalar()
        .fetch_one(&mut *tx)
        .await
        .map_err(super::ScimError::from)?;

    let mut list_qb: QueryBuilder<'_, sqlx::Postgres> = QueryBuilder::new(
        "SELECT users.id, users.email, users.email_lower, users.display_name, \
         users.email_verified_at, users.password_hash, users.password_updated_at, \
         users.password_hash_version, users.mfa_enrolled_at, users.active, \
         users.external_id, users.row_version, users.created_at, users.updated_at, \
         users.deleted_at \
         FROM users \
         JOIN user_org_memberships m ON m.user_id = users.id \
         WHERE m.org_id = ",
    );
    list_qb.push_bind(auth.org_id);
    list_qb.push(" AND users.deleted_at IS NULL AND m.deleted_at IS NULL");
    if let Some(filter) = &parsed_filter {
        list_qb.push(" AND ");
        push_filter(&mut list_qb, ResourceKind::User, filter)?;
    }
    list_qb.push(" ORDER BY ");
    if let Some(col) = sort_col {
        list_qb.push(col.sql);
    } else {
        list_qb.push("users.id");
    }
    list_qb.push(" ");
    list_qb.push(sort_dir.as_sql());
    list_qb.push(" OFFSET ");
    list_qb.push_bind(offset);
    list_qb.push(" LIMIT ");
    list_qb.push_bind(count);
    let rows = list_qb
        .build()
        .fetch_all(&mut *tx)
        .await
        .map_err(super::ScimError::from)?;
    let users = rows
        .iter()
        .map(user_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    tx.commit().await?;
    let resources: Vec<Value> = users
        .iter()
        .map(|u| to_scim_user(u, &state.base_url))
        .collect();
    let body = json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    });
    Ok(scim_json(StatusCode::OK, &body))
}

/// `POST /scim/v2/Users`.
#[allow(clippy::too_many_lines)] // clippy(pedantic): SCIM handler; splitting battle-tested §12 logic risks regression for no behaviour gain
pub async fn create_user(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let payload: UserPayload =
        serde_json::from_slice(&body).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed json: {err}"),
        })?;
    let user_name = payload
        .user_name
        .as_deref()
        .ok_or_else(|| ScimError::InvalidValue {
            detail: "userName is required".to_string(),
        })?;
    let display_name = payload.display_name_or(user_name);
    let primary_email = payload.primary_email().unwrap_or(user_name);

    let mut tx = state.pool.begin().await?;
    let existing_global = state
        .users
        .find_by_email_lower_in_tx(&mut tx, primary_email)
        .await?;
    let user = if let Some(existing) = existing_global {
        let collides = sqlx::query!(
            r#"
            SELECT 1 AS hit
            FROM federated_identities f
            JOIN org_idps i ON i.id = f.org_idp_id
            WHERE f.user_id = $1
              AND i.org_id <> $2
            LIMIT 1
            "#,
            existing.id,
            auth.org_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if collides {
            tx.rollback().await.ok();
            return Err(ScimError::Uniqueness {
                detail: "userName collides with another tenant's federated identity".to_string(),
            });
        }
        let same_org = state
            .memberships
            .find_for_user_org_in_tx(&mut tx, existing.id, auth.org_id)
            .await?;
        if same_org.is_some() {
            tx.rollback().await.ok();
            return Err(ScimError::Uniqueness {
                detail: "userName already exists in this org".to_string(),
            });
        }
        existing
    } else {
        state
            .users
            .create_in_tx(
                &mut tx,
                NewUser {
                    id: Uuid::now_v7(),
                    email: primary_email,
                    display_name: &display_name,
                    password_hash: None,
                    password_updated_at: None,
                    password_hash_version: 0,
                    external_id: payload.external_id.as_deref(),
                },
            )
            .await
            .map_err(map_user_err)?
    };

    state
        .memberships
        .create_in_tx(
            &mut tx,
            NewMembership {
                id: Uuid::now_v7(),
                user_id: user.id,
                org_id: auth.org_id,
                basic_role: "member",
                joined_via: "scim",
                jit_provisioned_at: Some(chrono::Utc::now()),
            },
        )
        .await
        .map_err(map_user_err)?;

    let active = payload.active.unwrap_or(true);
    let user = state
        .users
        .scim_update_in_tx(
            &mut tx,
            auth.org_id,
            user.id,
            &display_name,
            payload.external_id.as_deref(),
            active,
            None,
        )
        .await
        .map_err(map_user_err)?;

    // Re-onboarding an existing user as `active=false` MUST only
    // affect sessions in THIS org — sessions in other orgs the
    // user belongs to stay live (cross-tenant blast radius bug
    // identified in section-12 round-2 review).
    if !active {
        state
            .sessions
            .revoke_for_user_in_org_in_tx(&mut tx, user.id, auth.org_id)
            .await?;
    }

    tx.commit().await?;
    record_audit(
        &state.auditor,
        AuditEventKind::ScimUserCreated,
        auth.org_id,
        auth.token_id,
        user.id,
    )
    .await;
    if !active {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUserDeactivated,
            auth.org_id,
            auth.token_id,
            user.id,
        )
        .await;
    }
    let body = to_scim_user(&user, &state.base_url);
    let etag = quoted_etag(user.updated_at, user.row_version);
    let location = user_location(&state.base_url, user.id);
    Ok(scim_json_with_headers(
        StatusCode::CREATED,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `GET /scim/v2/Users/{id}`.
pub async fn get_user(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let user_id = parse_user_id(&id)?;
    let user = state
        .users
        .find_in_org(auth.org_id, user_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    let body = to_scim_user(&user, &state.base_url);
    let etag = quoted_etag(user.updated_at, user.row_version);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        None,
    ))
}

/// `PATCH /scim/v2/Users/{id}` (RFC 7644 §3.5.2).
pub async fn patch_user(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let user_id = parse_user_id(&id)?;
    let if_match = super::etag::parse_if_match(&headers);
    let unconditional = if_match.is_none();
    let ops: Vec<PatchOpInput> = parse_patch_ops(&body, auth.tolerant_mode)?;

    let mut tx = state.pool.begin().await?;
    let current = state
        .users
        .find_in_org_in_tx(&mut tx, auth.org_id, user_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    if let Some(tag) = &if_match
        && !version_matches(tag, current.updated_at, current.row_version)
    {
        tx.rollback().await.ok();
        return Err(ScimError::PreconditionFailed);
    }

    let mut snapshot = UserDraft::from(&current);
    apply_user_patch_ops(&mut snapshot, &ops)?;

    let updated = state
        .users
        .scim_update_in_tx(
            &mut tx,
            auth.org_id,
            current.id,
            &snapshot.display_name,
            snapshot.external_id.as_deref(),
            snapshot.active,
            Some(current.row_version),
        )
        .await
        .map_err(map_user_err)?;

    let was_deactivated = current.active && !updated.active;
    if was_deactivated {
        state
            .sessions
            .revoke_all_for_user_in_tx(&mut tx, updated.id)
            .await?;
    }
    tx.commit().await?;

    if unconditional {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUnconditionalWrite,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    }
    if was_deactivated {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUserDeactivated,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    } else {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUserUpdated,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    }
    let body = to_scim_user(&updated, &state.base_url);
    let etag = quoted_etag(updated.updated_at, updated.row_version);
    let location = user_location(&state.base_url, updated.id);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `PUT /scim/v2/Users/{id}` — full replace.
pub async fn put_user(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let user_id = parse_user_id(&id)?;
    let if_match = super::etag::parse_if_match(&headers);
    let unconditional = if_match.is_none();
    let payload: UserPayload =
        serde_json::from_slice(&body).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed json: {err}"),
        })?;

    let mut tx = state.pool.begin().await?;
    let current = state
        .users
        .find_in_org_in_tx(&mut tx, auth.org_id, user_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    if let Some(tag) = &if_match
        && !version_matches(tag, current.updated_at, current.row_version)
    {
        tx.rollback().await.ok();
        return Err(ScimError::PreconditionFailed);
    }

    let active = payload.active.unwrap_or(true);
    let display_name = payload.display_name_or(&current.display_name);
    let updated = state
        .users
        .scim_update_in_tx(
            &mut tx,
            auth.org_id,
            current.id,
            &display_name,
            payload
                .external_id
                .as_deref()
                .or(current.external_id.as_deref()),
            active,
            Some(current.row_version),
        )
        .await
        .map_err(map_user_err)?;

    let was_deactivated = current.active && !updated.active;
    if was_deactivated {
        state
            .sessions
            .revoke_all_for_user_in_tx(&mut tx, updated.id)
            .await?;
    }
    tx.commit().await?;

    if unconditional {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUnconditionalWrite,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    }
    if was_deactivated {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUserDeactivated,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    } else {
        record_audit(
            &state.auditor,
            AuditEventKind::ScimUserUpdated,
            auth.org_id,
            auth.token_id,
            updated.id,
        )
        .await;
    }
    let body = to_scim_user(&updated, &state.base_url);
    let etag = quoted_etag(updated.updated_at, updated.row_version);
    let location = user_location(&state.base_url, updated.id);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `DELETE /scim/v2/Users/{id}` — soft-delete + cascade.
pub async fn delete_user(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let user_id = parse_user_id(&id)?;
    let mut tx = state.pool.begin().await?;
    let current = state
        .users
        .find_in_org(auth.org_id, user_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    crate::repo::cascade::soft_delete_user(&mut tx, current.id).await?;
    tx.commit().await?;
    record_audit(
        &state.auditor,
        AuditEventKind::ScimUserDeleted,
        auth.org_id,
        auth.token_id,
        current.id,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Mutable-snapshot view over a [`User`] used by the PATCH op
/// applier to accumulate changes before the single-statement
/// `scim_update_in_tx`.
#[derive(Debug, Clone)]
pub struct UserDraft {
    /// Pending `display_name` value.
    pub display_name: String,
    /// Pending `external_id` value.
    pub external_id: Option<String>,
    /// Pending `active` value.
    pub active: bool,
}

impl From<&User> for UserDraft {
    fn from(u: &User) -> Self {
        Self {
            display_name: u.display_name.clone(),
            external_id: u.external_id.clone(),
            active: u.active,
        }
    }
}

fn parse_user_id(raw: &str) -> Result<Uuid, ScimError> {
    Uuid::parse_str(raw).map_err(|_| ScimError::NotFound)
}

pub(crate) fn require_scim_content_type(headers: &HeaderMap) -> Result<(), ScimError> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map_or_else(
            || Err(ScimError::UnsupportedMediaType),
            |value| {
                let semi = value.find(';').map_or(value.len(), |idx| idx);
                let mime = value[..semi].trim();
                if mime.eq_ignore_ascii_case(super::SCIM_CONTENT_TYPE)
                    || mime.eq_ignore_ascii_case("application/json")
                {
                    Ok(())
                } else {
                    Err(ScimError::UnsupportedMediaType)
                }
            },
        )
}

fn map_user_err(err: crate::error::IdentityError) -> ScimError {
    use crate::error::IdentityError;
    match err {
        IdentityError::EmailAlreadyExists => ScimError::Uniqueness {
            detail: "userName already exists".to_string(),
        },
        IdentityError::MembershipAlreadyExists => ScimError::Uniqueness {
            detail: "user already a member of this org".to_string(),
        },
        other => other.into(),
    }
}

pub(crate) async fn record_audit(
    auditor: &Arc<dyn zagrosi_core::Auditor>,
    kind: AuditEventKind,
    org_id: Uuid,
    token_id: Uuid,
    user_id: Uuid,
) {
    let Ok(service_name) = ServiceName::parse("scim-server") else {
        return;
    };
    let event = AuditEventV1::new(
        kind,
        AuditActor::Service { service_name },
        AuditResource::User { user_id },
        Uuid::now_v7(),
        org_id,
        AuditPayload::new(json!({"scim_token_id": token_id.to_string()})),
    );
    auditor.record(AuditEvent::V1(event)).await;
}
