-- 016 — service_tokens.
--
-- Internal service-to-service bearer tokens (`svc_*`) consumed by
-- the service-token surface. `service_name` identifies the caller (e.g.
-- `email-worker`); `allowed_subjects` is a NATS subject allowlist
-- (e.g. `identity.>`, `email.outbox.queue`) the worker is permitted
-- to publish to / subscribe on.
--
-- This table is intentionally org-agnostic: service tokens authorise
-- platform-wide internal callers. The tenant-isolation layer's RLS must whitelist this
-- table for the service / migration roles rather than gating it by
-- tenant, since there is no `org_id` to scope on.

CREATE TABLE service_tokens (
    id                UUID PRIMARY KEY,
    service_name      TEXT NOT NULL,
    token_hash        BYTEA NOT NULL,
    allowed_subjects  TEXT[] NOT NULL DEFAULT '{}',
    display_name      TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ NULL,
    deleted_at        TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX service_tokens_token_hash_unique_live
    ON service_tokens (token_hash)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;

CREATE INDEX service_tokens_service_name_idx ON service_tokens (service_name);
