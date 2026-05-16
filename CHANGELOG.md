# Changelog

All notable changes to the Zagrosi platform are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- identity: `zagrosi-identity` foundation crate and `zagrosi-core`
  ports for `AuthContext`, `AuditEvent`, `Auditor`, `EmailTransport`,
  `BreachListClient`, `KeyProvider`, `RateLimiter`, `MfaPolicy`, and
  `SessionIntrospector`.
- identity: password sign-up, sign-in, sign-out, email verification,
  and password reset with NIST 800-63B length policy, HIBP
  k-anonymity support, anti-enumeration responses, dummy verify on
  unknown sign-in email, and Argon2id calibration.
- identity: browser sessions with `sid_<43>` token format,
  `__Host-zagrosi_sid` cookies, double-submit CSRF, active-org
  switching, in-process LRU cache, fail-closed degraded TTL, and NATS
  revocation hints.
- identity: personal access tokens with `pat_<43>` format, scope
  checks, per-token rate limiting, last-used write-behind, and
  self-revoke support.
- identity: OIDC Authorization Code with PKCE S256, RFC 9207 `iss`
  validation, nonce and ID-token checks, JIT linking through
  `federated_identities`, refresh-token chain replay detection,
  discovery pre-warm, and optional JWKS thumbprint pinning.
- identity: feature-gated SAML SP with AuthnRequest, strict ACS
  validation order, replay table, metadata export, signed-node-only
  extraction, and negative/fuzz corpus coverage.
- identity: SCIM 2.0 Users, Groups, discovery endpoints, bearer
  tokens, CIDR allowlist, RFC 7644 filter grammar, ETag and
  `If-Match`, pagination, sorting, PATCH, and SCIM token issuance.
- identity: multi-IdP routing with DNSSEC domain verification,
  resolver quorum, PSL plus curated catch-all blocklist, and
  tombstone-aware SSO linking.
- identity: Valkey-backed rate limiting with per-IP sliding window,
  per-account lockout, admin unlock, `Retry-After`, and `RateLimit-*`
  headers.
- identity: email outbox worker with NATS wakeup, SMTP transport,
  idempotency keys, retry backoff, dead-letter state, and Fluent
  templates.
- identity: service-token CRUD with `svc_<43>` format and constrained
  allowed NATS subjects.
- identity: AES-256-GCM secrets envelope for persisted client secrets
  and SAML SP keys.
- identity: deterministic test compose stack with Authentik,
  SimpleSAMLphp, and Mailpit plus CI jobs `rust / sso-integration`,
  `rust / fuzz-smoke`, and `rust / signin-bench`.
- identity: Criterion performance benches and warm session-resolve
  throughput gate.
- docs: OpenAPI spec at `documentation/api/identity.openapi.yaml` and
  operator handoff at `documentation/identity.md`.

### Changed

- ci: branch-protection payload now requires `rust / sso-integration`,
  `rust / signin-bench`, and `rust / fuzz-smoke`.

### Deferred

- KMS-backed envelope and Argon2 pepper.
- Per-tenant SMTP transport.
- Account-merge admin UX.
- TOTP and WebAuthn MFA.
- Idle-account Argon2 background rehash job.
- Offline-mirror HIBP client.
- SAML SP signing-key rotation flow.
- SCIM Bulk support.
- zxcvbn-style entropy estimator.

### Security

- Sign-up and password-reset request paths are anti-enumeration by
  construction.
- SSO account linking is anchored on `(protocol, issuer, subject)`;
  email is not an SSO key.
- IdP-initiated SAML is disabled by default.
- SCIM bearer authentication and CIDR allowlist checks run before
  resource lookup.
- Persisted secrets use the identity secrets envelope rather than
  plaintext columns.
