-- 010 — email_outbox.
--
-- Durable outgoing-mail queue consumed by the email-outbox worker. `org_id` is
-- nullable for system mail (e.g. `account_already_exists` to a known
-- email when sign-up should leak nothing). `idempotency_key` enforces
-- exactly-once enqueue; the worker dequeue path uses
-- `(state, next_attempt_at)` with `FOR UPDATE SKIP LOCKED`.

CREATE TABLE email_outbox (
    id               UUID PRIMARY KEY,
    org_id           UUID NULL REFERENCES orgs (id),
    to_address       TEXT NOT NULL,
    from_address     TEXT NOT NULL,
    subject          TEXT NOT NULL,
    body_text        TEXT NOT NULL,
    body_html        TEXT NULL,
    template_key     TEXT NOT NULL,
    locale           TEXT NOT NULL DEFAULT 'en',
    idempotency_key  TEXT NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('queued','sending','sent','failed','dead')),
    attempts         INT NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ NULL,
    last_error       TEXT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at          TIMESTAMPTZ NULL
);

-- Per-tenant idempotency. `NULLS NOT DISTINCT` lets system mail
-- (org_id NULL) collapse into a single global slot per key, while
-- tenant mail dedupes within each org.
CREATE UNIQUE INDEX email_outbox_org_idempotency_unique
    ON email_outbox (org_id, idempotency_key)
    NULLS NOT DISTINCT;

CREATE INDEX email_outbox_dispatch_idx
    ON email_outbox (state, next_attempt_at);
