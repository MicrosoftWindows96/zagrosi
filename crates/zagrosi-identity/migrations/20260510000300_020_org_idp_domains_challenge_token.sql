-- 020 — org_idp_domains.challenge_token (section-13 domain-ownership flow).
--
-- The multi-IdP routing layer issues a per-domain DNS TXT challenge
-- (`vrf_<43-char-base64url>`) when an admin claims a domain. The
-- token is published as `_zagrosi-verify.<domain> IN TXT "<token>"`
-- and matched against the value the verify endpoint resolves through
-- the dual-resolver DNSSEC path (1.1.1.1 + 9.9.9.9).
--
-- The column is `NOT NULL DEFAULT ''` so existing pre-section-13 rows
-- (claimed under section-08's earlier scaffolding without a TXT
-- challenge) keep loading. The application layer always writes a
-- real `vrf_*` token at insert time; the empty-string default is the
-- migration-only escape hatch and is rejected by the verify endpoint.

ALTER TABLE org_idp_domains
    ADD COLUMN challenge_token TEXT NOT NULL DEFAULT '';
