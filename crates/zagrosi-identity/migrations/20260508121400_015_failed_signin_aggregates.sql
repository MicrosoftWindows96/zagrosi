-- 015 — failed_signin_aggregates.
--
-- Per-window aggregate of failed sign-in attempts. Used by
-- the rate-limit module for backoff + by audit. `user_id` is
-- nullable because the unknown-email path (no user matches) still
-- aggregates by IP. The `(user_id, window_start)` UNIQUE uses
-- `NULLS NOT DISTINCT` (PG 17+) so the upsert key works for the
-- unknown-email path; the `(ip, window_start)` UNIQUE supports
-- IP-pivot audits.

-- `org_id` is nullable because the unknown-email path (no matching user)
-- aggregates by IP only and has no tenant anchor. The tenant-isolation layer's RLS will use
-- `(org_id IS NULL OR org_id = current_setting('app.org_id'))` so the
-- IP-only path remains visible to system-level reads while tenant-scoped
-- rows stay isolated.
--
-- The `(ip, window_start)` index is *not* unique: shared NAT / CGN traffic
-- regularly routes many users through one IPv4 address inside one minute,
-- so a unique constraint there would reject genuine concurrent failures
-- from different users.
CREATE TABLE failed_signin_aggregates (
    id                UUID PRIMARY KEY,
    org_id            UUID NULL REFERENCES orgs (id),
    user_id           UUID NULL REFERENCES users (id),
    ip                INET NOT NULL,
    window_start      TIMESTAMPTZ NOT NULL,
    count             INT NOT NULL DEFAULT 0,
    first_attempt_at  TIMESTAMPTZ NOT NULL,
    last_attempt_at   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX failed_signin_aggregates_user_window_unique
    ON failed_signin_aggregates (user_id, window_start)
    NULLS NOT DISTINCT;

CREATE INDEX failed_signin_aggregates_ip_window_idx
    ON failed_signin_aggregates (ip, window_start);

CREATE INDEX failed_signin_aggregates_org_id_idx
    ON failed_signin_aggregates (org_id)
    WHERE org_id IS NOT NULL;
