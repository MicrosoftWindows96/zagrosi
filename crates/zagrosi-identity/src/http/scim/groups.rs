// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! SCIM 2.0 `Groups` resource HTTP handlers.
//!
//! Mirrors the structure of [`super::users`]. Group CRUD is
//! tenant-scoped via `OrgScoped<GroupRepo>`; the bearer's `org_id`
//! is the only org the handler can read or write. Cross-org IDs
//! resolve to `404 not_found` via the same JOIN-on-membership
//! invariant used by the Users surface.

use std::collections::BTreeMap;

use axum::extract::{Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::QueryBuilder;
use uuid::Uuid;
use zagrosi_core::{
    AuditActor, AuditEvent, AuditEventKind, AuditEventV1, AuditPayload, ServiceName,
};

use crate::domain::Group;
use crate::repo::{NewGroup, OrgScoped, group_from_row, with_org_context};

use super::etag::{quoted_etag, version_matches};
use super::filter::ResourceKind;
use super::patch::{apply_group_patch_ops, parse_patch_ops};
use super::translate::{SortDir, push_filter};
use super::users::require_scim_content_type;
use super::{
    SCIM_GROUP_SCHEMA, SCIM_LIST_RESPONSE_SCHEMA, SCIM_MAX_COUNT, ScimAuth, ScimError, ScimState,
    scim_json, scim_json_with_headers,
};

/// SCIM `Group` POST/PUT request body.
#[derive(Debug, Deserialize)]
pub struct GroupPayload {
    /// SCIM 2.0 schemas array.
    #[serde(default)]
    pub schemas: Vec<String>,
    /// SCIM `displayName`.
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    /// SCIM `externalId`.
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    /// SCIM `members` array.
    #[serde(default)]
    pub members: Vec<MemberPayload>,
    /// Catch-all for unknown attributes.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// SCIM `Group.members[]` element.
#[derive(Debug, Deserialize)]
pub struct MemberPayload {
    /// `value` — UUID of the user.
    #[serde(default)]
    pub value: Option<String>,
    /// `display` — display name (informational).
    #[serde(default)]
    pub display: Option<String>,
}

/// Query string for `GET /scim/v2/Groups`.
#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// SCIM filter expression.
    #[serde(default)]
    pub filter: Option<String>,
    /// 1-based start index.
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<i64>,
    /// Page size cap.
    #[serde(default)]
    pub count: Option<i64>,
    /// `sortBy` whitelist.
    #[serde(default, rename = "sortBy")]
    pub sort_by: Option<String>,
    /// `sortOrder`.
    #[serde(default, rename = "sortOrder")]
    pub sort_order: Option<String>,
    /// `attributes` projection (accepted but unused).
    #[serde(default)]
    pub attributes: Option<String>,
}

/// Mutable-snapshot view of a [`Group`] used by the PATCH applier.
#[derive(Debug, Clone)]
pub struct GroupDraft {
    /// Pending `display_name`.
    pub display_name: String,
    /// Pending `external_id`.
    pub external_id: Option<String>,
    /// User IDs to add to the group.
    pub member_adds: Vec<Uuid>,
    /// User IDs to remove from the group.
    pub member_removes: Vec<Uuid>,
    /// Whether `replace` of `members` reset semantics fired —
    /// caller MUST drop existing memberships before applying
    /// `member_adds`.
    pub member_resets: bool,
}

impl From<&Group> for GroupDraft {
    fn from(g: &Group) -> Self {
        Self {
            display_name: g.display_name.clone(),
            external_id: g.external_id.clone(),
            member_adds: Vec::new(),
            member_removes: Vec::new(),
            member_resets: false,
        }
    }
}

/// Project a [`Group`] + its current members into a SCIM JSON
/// body. `base_url` is prepended to `meta.location` and to each
/// member's `$ref` so the response carries absolute URIs when the
/// deployment configures one (RFC 7643 §3.1 SHOULD-recommendation;
/// RFC 7643 §4.2 mandates `$ref` be a fully qualified resource URL
/// when present).
#[must_use]
pub fn to_scim_group(group: &Group, member_ids: &[Uuid], base_url: &str) -> Value {
    let members: Vec<Value> = member_ids
        .iter()
        .map(|id| {
            json!({
                "value": id.to_string(),
                "$ref": format!("{base_url}/scim/v2/Users/{id}"),
                "type": "User"
            })
        })
        .collect();
    json!({
        "schemas": [SCIM_GROUP_SCHEMA],
        "id": group.id.to_string(),
        "displayName": group.display_name,
        "externalId": group.external_id,
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": group.created_at.to_rfc3339(),
            "lastModified": group.updated_at.to_rfc3339(),
            "version": quoted_etag(group.updated_at, group.row_version),
            "location": group_location(base_url, group.id)
        }
    })
}

/// Build the canonical `meta.location` for a `Groups/{id}` URI.
#[must_use]
pub(crate) fn group_location(base_url: &str, id: Uuid) -> String {
    format!("{base_url}/scim/v2/Groups/{id}")
}

/// `GET /scim/v2/Groups` — list groups in the bearer's org.
///
/// Filter, sort, paginate. The page + every member list resolve
/// inside a single `REPEATABLE READ` transaction so the
/// `ListResponse` is an atomic snapshot — concurrent member
/// PATCHes cannot tear the response.
pub async fn list_groups(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Query(q): Query<ListQuery>,
) -> Result<Response, ScimError> {
    let parsed_filter = match q.filter.as_deref() {
        Some(raw) => Some(super::filter::parse(raw)?),
        None => None,
    };
    let sort_col = match q.sort_by.as_deref() {
        Some(name) => Some(super::attrs::group_sort_column(name)?),
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
    // RLS: org context from the SCIM bearer token, set before any
    // tenanted statement in this transaction (section-05 policies).
    with_org_context(&mut tx, auth.org_id)
        .await
        .map_err(ScimError::from)?;

    let mut total_qb: QueryBuilder<'_, sqlx::Postgres> =
        QueryBuilder::new("SELECT COUNT(*) FROM groups WHERE org_id = ");
    total_qb.push_bind(auth.org_id);
    total_qb.push(" AND deleted_at IS NULL");
    if let Some(filter) = &parsed_filter {
        total_qb.push(" AND ");
        push_filter(&mut total_qb, ResourceKind::Group, filter)?;
    }
    let total: i64 = total_qb
        .build_query_scalar()
        .fetch_one(&mut *tx)
        .await
        .map_err(super::ScimError::from)?;

    let mut list_qb: QueryBuilder<'_, sqlx::Postgres> = QueryBuilder::new(
        "SELECT id, org_id, display_name, external_id, row_version, \
         created_at, updated_at, deleted_at \
         FROM groups WHERE org_id = ",
    );
    list_qb.push_bind(auth.org_id);
    list_qb.push(" AND deleted_at IS NULL");
    if let Some(filter) = &parsed_filter {
        list_qb.push(" AND ");
        push_filter(&mut list_qb, ResourceKind::Group, filter)?;
    }
    list_qb.push(" ORDER BY ");
    if let Some(col) = sort_col {
        list_qb.push(col.sql);
    } else {
        list_qb.push("groups.id");
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
    let groups = rows
        .iter()
        .map(group_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    let mut resources: Vec<Value> = Vec::with_capacity(groups.len());
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    for group in &groups {
        let members = scoped
            .list_members_in_tx(&mut tx, group.id)
            .await?
            .into_iter()
            .map(|m| m.user_id)
            .collect::<Vec<_>>();
        resources.push(to_scim_group(group, &members, &state.base_url));
    }
    tx.commit().await?;

    let body = json!({
        "schemas": [SCIM_LIST_RESPONSE_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    });
    Ok(scim_json(StatusCode::OK, &body))
}

/// `POST /scim/v2/Groups`.
pub async fn create_group(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let payload: GroupPayload =
        serde_json::from_slice(&body).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed json: {err}"),
        })?;
    let display_name = payload
        .display_name
        .as_deref()
        .ok_or_else(|| ScimError::InvalidValue {
            detail: "displayName is required".to_string(),
        })?;

    let mut tx = state.pool.begin().await?;
    // RLS: org context from the SCIM bearer token, set before any
    // tenanted statement in this transaction (section-05 policies).
    with_org_context(&mut tx, auth.org_id)
        .await
        .map_err(ScimError::from)?;
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    let group = scoped
        .create_group_in_tx(
            &mut tx,
            NewGroup {
                id: Uuid::now_v7(),
                display_name,
                external_id: payload.external_id.as_deref(),
            },
        )
        .await
        .map_err(map_group_err)?;

    let mut member_ids = Vec::new();
    for member in &payload.members {
        let Some(value) = member.value.as_deref() else {
            continue;
        };
        let Ok(uid) = Uuid::parse_str(value) else {
            tx.rollback().await.ok();
            return Err(ScimError::InvalidValue {
                detail: format!("member value '{value}' is not a UUID"),
            });
        };
        ensure_user_in_org(&state, &mut tx, auth.org_id, uid).await?;
        scoped.add_member_in_tx(&mut tx, group.id, uid).await?;
        member_ids.push(uid);
    }
    if !payload.members.is_empty() {
        scoped.bump_group_version_in_tx(&mut tx, group.id).await?;
    }
    let group = scoped
        .find_group_in_tx(&mut tx, group.id)
        .await?
        .ok_or(ScimError::NotFound)?;
    tx.commit().await?;

    audit_group(
        &state,
        AuditEventKind::ScimGroupCreated,
        auth.org_id,
        auth.token_id,
        group.id,
    )
    .await;
    let body = to_scim_group(&group, &member_ids, &state.base_url);
    let etag = quoted_etag(group.updated_at, group.row_version);
    let location = group_location(&state.base_url, group.id);
    Ok(scim_json_with_headers(
        StatusCode::CREATED,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `GET /scim/v2/Groups/{id}`.
pub async fn get_group(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let group_id = parse_id(&id)?;
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    let group = scoped
        .find_group(group_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    let members = scoped
        .list_members(group.id)
        .await?
        .into_iter()
        .map(|m| m.user_id)
        .collect::<Vec<_>>();
    let body = to_scim_group(&group, &members, &state.base_url);
    let etag = quoted_etag(group.updated_at, group.row_version);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        None,
    ))
}

/// `PATCH /scim/v2/Groups/{id}`.
#[allow(clippy::too_many_lines)] // clippy(pedantic): SCIM handler; splitting battle-tested §12 logic risks regression for no behaviour gain
pub async fn patch_group(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let group_id = parse_id(&id)?;
    let if_match = super::etag::parse_if_match(&headers);
    let unconditional = if_match.is_none();
    let ops = parse_patch_ops(&body, auth.tolerant_mode)?;

    let mut tx = state.pool.begin().await?;
    // RLS: org context from the SCIM bearer token, set before any
    // tenanted statement in this transaction (section-05 policies).
    with_org_context(&mut tx, auth.org_id)
        .await
        .map_err(ScimError::from)?;
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    let current = scoped
        .find_group_in_tx(&mut tx, group_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    if let Some(tag) = &if_match
        && !version_matches(tag, current.updated_at, current.row_version)
    {
        tx.rollback().await.ok();
        return Err(ScimError::PreconditionFailed);
    }

    let mut snapshot = GroupDraft::from(&current);
    apply_group_patch_ops(&mut snapshot, &ops)?;

    let updated = scoped
        .update_group_in_tx(
            &mut tx,
            current.id,
            &snapshot.display_name,
            snapshot.external_id.as_deref(),
            Some(current.row_version),
        )
        .await
        .map_err(map_group_err)?;

    if snapshot.member_resets {
        sqlx::query!(
            r#"
            UPDATE group_memberships AS gm
            SET deleted_at = now()
            FROM groups g
            WHERE gm.group_id = $1
              AND g.id = gm.group_id
              AND g.org_id = $2
              AND gm.deleted_at IS NULL
            "#,
            current.id,
            auth.org_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    for uid in &snapshot.member_removes {
        scoped
            .remove_member_in_tx(&mut tx, current.id, *uid)
            .await?;
    }
    for uid in &snapshot.member_adds {
        ensure_user_in_org(&state, &mut tx, auth.org_id, *uid).await?;
        scoped.add_member_in_tx(&mut tx, current.id, *uid).await?;
    }
    if snapshot.member_resets
        || !snapshot.member_adds.is_empty()
        || !snapshot.member_removes.is_empty()
    {
        scoped.bump_group_version_in_tx(&mut tx, current.id).await?;
    }
    let final_group = scoped
        .find_group_in_tx(&mut tx, current.id)
        .await?
        .ok_or(ScimError::NotFound)?;
    let members = scoped
        .list_members_in_tx(&mut tx, current.id)
        .await?
        .into_iter()
        .map(|m| m.user_id)
        .collect::<Vec<_>>();
    tx.commit().await?;

    if unconditional {
        audit_group(
            &state,
            AuditEventKind::ScimUnconditionalWrite,
            auth.org_id,
            auth.token_id,
            current.id,
        )
        .await;
    }
    audit_group(
        &state,
        AuditEventKind::ScimGroupUpdated,
        auth.org_id,
        auth.token_id,
        current.id,
    )
    .await;
    let _ = updated; // value already reflected via final_group fetch
    let body = to_scim_group(&final_group, &members, &state.base_url);
    let etag = quoted_etag(final_group.updated_at, final_group.row_version);
    let location = group_location(&state.base_url, final_group.id);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `PUT /scim/v2/Groups/{id}` — full replace.
#[allow(clippy::too_many_lines)] // clippy(pedantic): SCIM handler; splitting battle-tested §12 logic risks regression for no behaviour gain
pub async fn put_group(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, ScimError> {
    require_scim_content_type(&headers)?;
    let group_id = parse_id(&id)?;
    let if_match = super::etag::parse_if_match(&headers);
    let unconditional = if_match.is_none();
    let payload: GroupPayload =
        serde_json::from_slice(&body).map_err(|err| ScimError::InvalidValue {
            detail: format!("malformed json: {err}"),
        })?;

    let mut tx = state.pool.begin().await?;
    // RLS: org context from the SCIM bearer token, set before any
    // tenanted statement in this transaction (section-05 policies).
    with_org_context(&mut tx, auth.org_id)
        .await
        .map_err(ScimError::from)?;
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    let current = scoped
        .find_group_in_tx(&mut tx, group_id)
        .await?
        .ok_or(ScimError::NotFound)?;
    if let Some(tag) = &if_match
        && !version_matches(tag, current.updated_at, current.row_version)
    {
        tx.rollback().await.ok();
        return Err(ScimError::PreconditionFailed);
    }

    let display_name = payload
        .display_name
        .as_deref()
        .unwrap_or(&current.display_name)
        .to_string();
    let external_id = payload
        .external_id
        .as_deref()
        .or(current.external_id.as_deref());
    scoped
        .update_group_in_tx(
            &mut tx,
            current.id,
            &display_name,
            external_id,
            Some(current.row_version),
        )
        .await
        .map_err(map_group_err)?;

    sqlx::query!(
        r#"
        UPDATE group_memberships AS gm
        SET deleted_at = now()
        FROM groups g
        WHERE gm.group_id = $1
          AND g.id = gm.group_id
          AND g.org_id = $2
          AND gm.deleted_at IS NULL
        "#,
        current.id,
        auth.org_id,
    )
    .execute(&mut *tx)
    .await?;

    let mut member_ids = Vec::new();
    for member in &payload.members {
        let Some(value) = member.value.as_deref() else {
            continue;
        };
        let Ok(uid) = Uuid::parse_str(value) else {
            tx.rollback().await.ok();
            return Err(ScimError::InvalidValue {
                detail: format!("member value '{value}' is not a UUID"),
            });
        };
        ensure_user_in_org(&state, &mut tx, auth.org_id, uid).await?;
        scoped.add_member_in_tx(&mut tx, current.id, uid).await?;
        member_ids.push(uid);
    }
    scoped.bump_group_version_in_tx(&mut tx, current.id).await?;
    let final_group = scoped
        .find_group_in_tx(&mut tx, current.id)
        .await?
        .ok_or(ScimError::NotFound)?;
    tx.commit().await?;

    if unconditional {
        audit_group(
            &state,
            AuditEventKind::ScimUnconditionalWrite,
            auth.org_id,
            auth.token_id,
            current.id,
        )
        .await;
    }
    audit_group(
        &state,
        AuditEventKind::ScimGroupUpdated,
        auth.org_id,
        auth.token_id,
        current.id,
    )
    .await;
    let body = to_scim_group(&final_group, &member_ids, &state.base_url);
    let etag = quoted_etag(final_group.updated_at, final_group.row_version);
    let location = group_location(&state.base_url, final_group.id);
    Ok(scim_json_with_headers(
        StatusCode::OK,
        &body,
        Some(&etag),
        Some(&location),
    ))
}

/// `DELETE /scim/v2/Groups/{id}` — soft-delete + tombstone members.
pub async fn delete_group(
    State(state): State<ScimState>,
    Extension(auth): Extension<ScimAuth>,
    Path(id): Path<String>,
) -> Result<Response, ScimError> {
    let group_id = parse_id(&id)?;
    let mut tx = state.pool.begin().await?;
    // RLS: org context from the SCIM bearer token, set before any
    // tenanted statement in this transaction (section-05 policies).
    with_org_context(&mut tx, auth.org_id)
        .await
        .map_err(ScimError::from)?;
    let scoped = OrgScoped::new(&state.groups, auth.org_id);
    scoped.soft_delete_group_in_tx(&mut tx, group_id).await?;
    tx.commit().await?;
    audit_group(
        &state,
        AuditEventKind::ScimGroupDeleted,
        auth.org_id,
        auth.token_id,
        group_id,
    )
    .await;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn ensure_user_in_org(
    state: &ScimState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<(), ScimError> {
    let m = state
        .memberships
        .find_for_user_org_in_tx(tx, user_id, org_id)
        .await?;
    if m.is_none() {
        return Err(ScimError::InvalidValue {
            detail: format!("user {user_id} is not a member of this org"),
        });
    }
    Ok(())
}

fn parse_id(raw: &str) -> Result<Uuid, ScimError> {
    Uuid::parse_str(raw).map_err(|_| ScimError::NotFound)
}

fn map_group_err(err: crate::error::IdentityError) -> ScimError {
    use crate::error::IdentityError;
    match err {
        IdentityError::GroupDisplayNameExists => ScimError::Uniqueness {
            detail: "displayName already exists".to_string(),
        },
        IdentityError::GroupNotFound => ScimError::NotFound,
        IdentityError::ScimPreconditionFailed => ScimError::PreconditionFailed,
        other => other.into(),
    }
}

async fn audit_group(
    state: &ScimState,
    kind: AuditEventKind,
    org_id: Uuid,
    token_id: Uuid,
    group_id: Uuid,
) {
    let Ok(service_name) = ServiceName::parse("scim-server") else {
        return;
    };
    let event = AuditEventV1::builder(
        kind,
        AuditActor::Service { service_name },
        Some(org_id),
        Uuid::now_v7(),
    )
    .metadata(AuditPayload::new(json!({
        "scim_token_id": token_id.to_string(),
        "group_id": group_id.to_string()
    })))
    .build();
    state.auditor.record(AuditEvent::V1(event)).await;
}
