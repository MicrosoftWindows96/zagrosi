// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown, clippy::too_long_first_doc_paragraph)]
//! `OrgIdpDomainRepo` — verified-domain → IdP claim persistence.
//!
//! Multi-tenant writes go through [`OrgScoped`] so callers cannot
//! leak across orgs. The cross-org routing lookup
//! ([`OrgIdpDomainRepo::lookup_routes_by_domain_lower`]) deliberately
//! bypasses `OrgScoped` because the domain itself is the public anchor:
//! the discover handler does not yet know which tenant the email
//! belongs to and the lookup cannot self-isolate.

use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{DomainRouteHit, OrgIdpDomain};
use crate::error::{IdentityError, Result, map_sqlx_error};

use super::OrgScoped;

/// Repository for `org_idp_domains`. Multi-tenant: writes MUST go
/// through [`OrgScoped`]. The single bare-repo method is the
/// routing-lookup path which is by design cross-org.
#[derive(Clone)]
pub struct OrgIdpDomainRepo {
    pool: PgPool,
}

impl OrgIdpDomainRepo {
    /// Wrap a connection pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Pool accessor.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cross-org routing lookup for the discover handler.
    ///
    /// Returns every verified, non-soft-deleted domain claim that
    /// matches `lower(domain)`, joined to its enabled, non-deleted
    /// IdP. Sorted by `(priority ASC, display_name ASC)` so the
    /// caller can pass the slice straight to the picker without
    /// re-sorting.
    ///
    /// `domain_lower` MUST already be normalised
    /// (`idna::domain_to_ascii` + `to_ascii_lowercase`); the lookup
    /// uses an exact-match equality predicate against the partial
    /// `(lower(domain), priority)` index.
    ///
    /// Cross-tenant defence: the join filters
    /// `org_idps.enabled = true AND deleted_at IS NULL` so a tenant
    /// with a verified-but-disabled IdP does not surface in the
    /// routing decision. Callers MUST treat the empty result as
    /// "no SSO routing — fall back to password" (the design contract
    /// of [`crate::routing::discover`]).
    pub async fn lookup_routes_by_domain_lower(
        &self,
        domain_lower: &str,
    ) -> Result<Vec<DomainRouteHit>> {
        let rows = sqlx::query!(
            r#"
            SELECT i.id          AS org_idp_id,
                   i.org_id      AS org_id,
                   i.protocol    AS protocol,
                   i.display_name AS display_name,
                   d.priority    AS priority
            FROM org_idp_domains AS d
            JOIN org_idps        AS i ON i.id = d.org_idp_id
            WHERE lower(d.domain) = $1
              AND d.verified_at IS NOT NULL
              AND d.deleted_at IS NULL
              AND i.enabled = TRUE
              AND i.deleted_at IS NULL
            ORDER BY d.priority ASC, i.display_name ASC
            "#,
            domain_lower,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| DomainRouteHit {
                org_idp_id: r.org_idp_id,
                org_id: r.org_id,
                protocol: r.protocol,
                display_name: r.display_name,
                priority: r.priority,
            })
            .collect())
    }
}

impl super::org_scoped::HasPool for OrgIdpDomainRepo {
    fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }
}

impl OrgScoped<'_, OrgIdpDomainRepo> {
    /// Insert a new domain claim. The unique partial index on
    /// `(lower(domain), org_idp_id) WHERE verified_at IS NOT NULL`
    /// only fires once verification flips `verified_at`, so create
    /// always succeeds for fresh placeholders even when another org
    /// holds a verified claim on the same domain.
    pub async fn create(&self, new: NewOrgIdpDomain<'_>) -> Result<OrgIdpDomain> {
        // Org-membership check: the claimed `org_idp_id` MUST belong
        // to this scope's org. Reject cross-org probes with
        // `OrgNotFound` (404) per the project-wide convention.
        let mut tx = self.begin_org_tx().await?;
        let belongs = sqlx::query!(
            r#"
            SELECT 1 AS sentinel
            FROM org_idps
            WHERE org_id = $1 AND id = $2 AND deleted_at IS NULL
            "#,
            self.org_id(),
            new.org_idp_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
        if !belongs {
            return Err(IdentityError::OrgNotFound);
        }

        let row = sqlx::query!(
            r#"
            INSERT INTO org_idp_domains (
                id, org_idp_id, domain, challenge_token,
                priority, org_id
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, org_idp_id, domain, challenge_token,
                      verified_at, last_verified_via,
                      priority, created_at, deleted_at
            "#,
            new.id,
            new.org_idp_id,
            new.domain,
            new.challenge_token,
            new.priority,
            self.org_id(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::OrgNotFound,
                IdentityError::InvalidDomain {
                    reason: "domain already claimed by this idp".into(),
                },
                None,
            )
        })?;
        tx.commit().await?;

        Ok(OrgIdpDomain {
            id: row.id,
            org_idp_id: row.org_idp_id,
            domain: row.domain,
            challenge_token: row.challenge_token,
            verified_at: row.verified_at,
            last_verified_via: row.last_verified_via,
            priority: row.priority,
            created_at: row.created_at,
            deleted_at: row.deleted_at,
        })
    }

    /// Find a live domain claim by id, scoped to this org and the
    /// given IdP. Cross-org IDs and IdPs that do not belong to this
    /// org both return `Ok(None)` per the cross-tenant
    /// no-existence-oracle convention.
    pub async fn find_in_idp(
        &self,
        org_idp_id: Uuid,
        domain_id: Uuid,
    ) -> Result<Option<OrgIdpDomain>> {
        let mut tx = self.begin_org_tx().await?;
        let row = sqlx::query!(
            r#"
            SELECT d.id, d.org_idp_id, d.domain, d.challenge_token,
                   d.verified_at, d.last_verified_via,
                   d.priority, d.created_at, d.deleted_at
            FROM org_idp_domains AS d
            JOIN org_idps        AS i ON i.id = d.org_idp_id
            WHERE i.org_id = $1
              AND d.org_idp_id = $2
              AND d.id = $3
              AND d.deleted_at IS NULL
              AND i.deleted_at IS NULL
            "#,
            self.org_id(),
            org_idp_id,
            domain_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(row.map(|r| OrgIdpDomain {
            id: r.id,
            org_idp_id: r.org_idp_id,
            domain: r.domain,
            challenge_token: r.challenge_token,
            verified_at: r.verified_at,
            last_verified_via: r.last_verified_via,
            priority: r.priority,
            created_at: r.created_at,
            deleted_at: r.deleted_at,
        }))
    }

    /// List live domain claims for `org_idp_id` within this org,
    /// sorted by `(priority ASC, domain ASC)`. Returns an empty
    /// vector when the IdP has no claims yet.
    pub async fn list_in_idp(&self, org_idp_id: Uuid) -> Result<Vec<OrgIdpDomain>> {
        let mut tx = self.begin_org_tx().await?;
        let rows = sqlx::query!(
            r#"
            SELECT d.id, d.org_idp_id, d.domain, d.challenge_token,
                   d.verified_at, d.last_verified_via,
                   d.priority, d.created_at, d.deleted_at
            FROM org_idp_domains AS d
            JOIN org_idps        AS i ON i.id = d.org_idp_id
            WHERE i.org_id = $1
              AND d.org_idp_id = $2
              AND d.deleted_at IS NULL
              AND i.deleted_at IS NULL
            ORDER BY d.priority ASC, d.domain ASC
            "#,
            self.org_id(),
            org_idp_id,
        )
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(rows
            .into_iter()
            .map(|r| OrgIdpDomain {
                id: r.id,
                org_idp_id: r.org_idp_id,
                domain: r.domain,
                challenge_token: r.challenge_token,
                verified_at: r.verified_at,
                last_verified_via: r.last_verified_via,
                priority: r.priority,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            })
            .collect())
    }

    /// Stamp `verified_at = now()` and `last_verified_via = $3` on
    /// the given domain row, scoped to this org via the IdP join.
    /// Returns the updated row so the caller can emit it back.
    ///
    /// # Errors
    ///
    /// - [`IdentityError::OrgNotFound`] when the row does not exist
    ///   in this org's scope (cross-org probe → 404).
    /// - [`IdentityError::InvalidDomain`] when the unique partial
    ///   index on verified rows fires (another verified claim of
    ///   `(lower(domain), org_idp_id)` already exists).
    pub async fn mark_verified(
        &self,
        org_idp_id: Uuid,
        domain_id: Uuid,
        last_verified_via: &str,
    ) -> Result<OrgIdpDomain> {
        let mut tx = self.begin_org_tx().await?;
        let row = sqlx::query!(
            r#"
            UPDATE org_idp_domains AS d
            SET verified_at = now(),
                last_verified_via = $4
            FROM org_idps AS i
            WHERE d.org_idp_id = i.id
              AND i.org_id = $1
              AND d.org_idp_id = $2
              AND d.id = $3
              AND d.deleted_at IS NULL
              AND i.deleted_at IS NULL
            RETURNING d.id, d.org_idp_id, d.domain, d.challenge_token,
                      d.verified_at, d.last_verified_via,
                      d.priority, d.created_at, d.deleted_at
            "#,
            self.org_id(),
            org_idp_id,
            domain_id,
            last_verified_via,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            map_sqlx_error(
                e,
                IdentityError::OrgNotFound,
                IdentityError::InvalidDomain {
                    reason: "domain already verified by another claim".into(),
                },
                None,
            )
        })?;
        tx.commit().await?;

        match row {
            Some(r) => Ok(OrgIdpDomain {
                id: r.id,
                org_idp_id: r.org_idp_id,
                domain: r.domain,
                challenge_token: r.challenge_token,
                verified_at: r.verified_at,
                last_verified_via: r.last_verified_via,
                priority: r.priority,
                created_at: r.created_at,
                deleted_at: r.deleted_at,
            }),
            None => Err(IdentityError::OrgNotFound),
        }
    }

    /// Soft-delete a domain claim. Returns `Some(domain)` when the
    /// row was flipped from live to tombstoned (the domain string is
    /// returned so the handler can populate the audit payload's
    /// `domain_lower` field consistently with the rest of the
    /// lifecycle events). Returns `None` for cross-org / unknown rows.
    pub async fn soft_delete(&self, org_idp_id: Uuid, domain_id: Uuid) -> Result<Option<String>> {
        let mut tx = self.begin_org_tx().await?;
        let row = sqlx::query!(
            r#"
            UPDATE org_idp_domains AS d
            SET deleted_at = now()
            FROM org_idps AS i
            WHERE d.org_idp_id = i.id
              AND i.org_id = $1
              AND d.org_idp_id = $2
              AND d.id = $3
              AND d.deleted_at IS NULL
              AND i.deleted_at IS NULL
            RETURNING d.domain
            "#,
            self.org_id(),
            org_idp_id,
            domain_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|r| r.domain))
    }
}

/// Argument bundle for [`OrgScoped::<OrgIdpDomainRepo>::create`].
#[derive(Debug)]
pub struct NewOrgIdpDomain<'a> {
    /// Application-generated UUID v7 for the new claim.
    pub id: Uuid,
    /// Owning IdP. MUST belong to this scope's org; the create call
    /// validates this and returns `OrgNotFound` on mismatch.
    pub org_idp_id: Uuid,
    /// Domain as entered (display case preserved).
    pub domain: &'a str,
    /// `vrf_*`-prefixed challenge token. The application layer mints
    /// this via [`crate::domain::token_format::mint`].
    pub challenge_token: &'a str,
    /// Picker priority. Lower wins; defaults to `100` at the
    /// application layer.
    pub priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(OrgIdpDomainRepo: Send, Sync, Clone);
    assert_impl_all!(NewOrgIdpDomain<'static>: Send, Sync);

    fn _last_verified_at_optional_in_tests(
        _d: OrgIdpDomain,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        // Compile-time pin: the helper takes Option<DateTime<Utc>>
        // so the routing tests can match `verified_at.is_some()`
        // without taking a stale snapshot of the field type.
        None
    }
}
