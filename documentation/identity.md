<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Identity, SSO, and SCIM

This document is the operator handoff for the Zagrosi identity foundation. It
covers architecture, threat model, deferred work, hardware baseline, environment
variables, standards conformance, and handoff notes for the RBAC, admin UI, and
KMS workstreams.

## Architecture Overview

The identity surface is split into five layers.

| Layer | Responsibility |
| --- | --- |
| Domain | Users, organisations, memberships, sessions, credentials, IdP config, SCIM resources, and token formats. |
| Persistence | SQLx repositories, tenant-scoped helpers, migrations, soft-delete cascade helpers, replay tables, and pending-auth tables. |
| Application | Password auth, OIDC, SAML, SCIM, email outbox, session lifecycle, rate limiting, and token services. |
| Transport | Axum HTTP handlers for browser auth, SCIM, SSO callbacks, session routes, PAT routes, SCIM token routes, service token routes, and admin unlock. |
| Infra adapters | PostgreSQL, Valkey, NATS, SMTP, DNSSEC resolvers, Authentik, SimpleSAMLphp, and Mailpit test compose. |

`zagrosi-core` owns stable ports and value objects: `AuthContext`,
`AuditEvent`, `Auditor`, `EmailTransport`, `BreachListClient`, `KeyProvider`,
`RateLimiter`, `MfaPolicy`, and `SessionIntrospector`. `zagrosi-identity`
implements those ports and keeps provider-specific dependencies out of
downstream crates.

Cross-cutting contracts:

- Persisted secret material is wrapped in an AES-256-GCM envelope with
  `{ key_id, nonce, ciphertext, tag }`.
- Tokens use fixed prefixes and 43 base64url characters:
  `sid_`, `pat_`, `scim_`, `svc_`, `vrf_`, and `rst_`.
- Browser sessions use `__Host-zagrosi_sid; Path=/; Secure; HttpOnly;
  SameSite=Lax` and a double-submit `__Host-zagrosi_csrf` cookie.
- Session revocation is database authoritative. NATS subjects such as
  `identity.session.revoked.<session_id>` are cache-eviction hints.
- Password hashing always runs inside a bounded `spawn_blocking` pool.
- Email sending is outbox-based. Producers insert rows in the same transaction
  as the user mutation; workers drain with `FOR UPDATE SKIP LOCKED`.

## Threat Model

| ID | Threat | Mitigation | Residual risk | Asserted by |
| --- | --- | --- | --- | --- |
| R1 | SAML C dependency expands the default binary surface. | `saml` feature gate; default builds do not link xmlsec, OpenSSL, or libxml2. | SAML-enabled deploys must patch system libraries. | `crates/zagrosi-identity/tests/saml_negative_corpus.rs` |
| R2 | Token database compromise. | Raw tokens are returned once and stored only as SHA-256 digests with the prefix in the hash input. | Stolen live bearer tokens remain usable until revocation or expiry. | `crates/zagrosi-identity/tests/api_tokens.rs::issue_persists_hashed_token_and_returns_raw` |
| R3 | Secrets-at-rest compromise. | AES-256-GCM envelope with redacted debug output. | Environment key compromise is total compromise for wrapped secrets. | `crates/zagrosi-identity/tests/crypto_secrets.rs::secrets_seal_open_roundtrip` |
| R4 | Account enumeration. | Sign-up and reset request paths return uniform success; sign-in uses dummy verify for unknown email. | Timing still depends on infrastructure jitter. | `crates/zagrosi-identity/tests/password_flow.rs::signin_unknown_email_returns_invalid_credentials` |
| R5 | Argon2 spraying. | Valkey sliding-window limits, lockout, and bounded Argon2 concurrency. | A very large botnet can still consume edge capacity. | `crates/zagrosi-identity/tests/rate_limit_valkey.rs::lockout_trips_at_threshold_and_admin_unlock_clears_state` |
| R6 | Session replay after password reset. | Resolver rejects sessions created before `password_updated_at`. | Read replicas can lag within the configured database topology. | `crates/zagrosi-identity/tests/tenant_isolation.rs::session_find_is_hash_only_by_design` |
| R7 | Cross-tenant data exposure. | Every multi-tenant repository is anchored on `org_id`; `with_org_context` sets `app.current_org_id`. | Future RLS rollout must preserve the helper contract. | `crates/zagrosi-identity/tests/tenant_isolation.rs::org_scoped_with_org_context_round_trip` |
| R8 | Performance target drift. | Criterion benches publish per-path numbers; warm session resolve is gated. | Hosted CI runners vary, so production qualification should use a stable bench runner. | `crates/zagrosi-identity/tests/bench_smoke.rs::bench_gate_script_fails_and_passes_on_fixture_estimates` |
| R9 | OIDC callback substitution. | PKCE S256, state cookie binding, nonce validation, ID token validation, and RFC 9207 `iss`. | Provider misconfiguration can still route users to the wrong IdP. | `crates/zagrosi-identity/tests/oidc_negative.rs::rejects_rfc9207_iss_mismatch` |
| R10 | OIDC refresh-token replay. | Refresh token chain records parent usage and revokes descendants on replay. | Provider outage can interrupt refresh renewal. | `crates/zagrosi-identity/tests/oidc_chain_invariants.rs::refresh_replay_revokes_chain` |
| R11 | SAML XML wrapping, XXE, and replay. | Strict ACS order, signed-node-only extraction, bearer checks, audience checks, and replay table insert before session issue. | xmlsec parser bugs remain a supply-chain risk. | `crates/zagrosi-identity/tests/saml_negative_corpus.rs` |
| R12 | SSO takeover by email-as-key. | SSO links by `(protocol, issuer, subject)` in `federated_identities`; email collision rejects or requires admin action. | Admin merge UX is deferred. | `crates/zagrosi-identity/tests/oidc_flow.rs::oidc_jit_links_to_existing_federated_identity_not_email` |
| R13 | Public email domain takeover. | DNSSEC domain verification plus PSL and curated catch-all blocklist. | PSL snapshot must be refreshed on cadence. | `crates/zagrosi-identity/tests/multi_idp_routing.rs::psl_blocks_gmail_outlook_yahoo` |
| R14 | SCIM confused-deputy access. | SCIM bearer lookup binds token to org before resource lookup; CIDR allowlist runs first. | Provider IP ranges must be maintained by operators. | `crates/zagrosi-identity/tests/scim_server.rs::cidr_allowlist_rejects_unlisted_peer_ip_with_403` |
| R15 | Email delivery loss or duplication. | Transactional outbox, idempotency keys, NATS wakeup plus polling, and retry cap. | External SMTP permanent failures need operator retry UX. | `crates/zagrosi-identity/tests/email_outbox.rs::idempotency_key_prevents_duplicate_enqueue_and_send` |

## Deferred Items

| Item | Target workstream | Blocking | Current readiness |
| --- | --- | --- | --- |
| KMS-backed envelope and Argon2 pepper | KMS | No | Envelope carries `key_id`; `password_hash_version` supports profile changes. |
| Per-tenant SMTP transport | Admin UI | No | `EmailTransport` trait is object safe and already supports alternate implementations. |
| Account-merge admin UX | Admin UI | No | SSO collision paths reject safely and preserve tombstones. |
| TOTP and WebAuthn MFA | MFA | No | `MfaPolicy` and `AuthContinuation` already model MFA-required continuations. |
| Idle-account Argon2 background rehash job | Operations | No | `needs_rehash` and `password_hash_version` are implemented. |
| Offline-mirror HIBP client | Security operations | No | `BreachListClient` trait already abstracts the provider. |
| SAML SP signing-key rotation flow | Identity operations | No | Metadata export and wrapped key storage are in place. |
| SCIM Bulk support | SCIM | No | `ServiceProviderConfig.bulk.supported` remains `false`. |
| zxcvbn-style entropy estimator | Password policy | No | Length policy is isolated and can add a feature-gated estimator. |

## Hardware Baseline

Hardware reference: 32 vCPU, 64 GiB RAM, NVMe disk, regional PostgreSQL 18, and
Valkey 8. Developer benches default to a low-cost Argon2 profile so local
`cargo bench` runs complete quickly; CI or release qualification can set
`ZAGROSI_ARGON2_M_COST=19456`, `ZAGROSI_ARGON2_T_COST=2`, and
`ZAGROSI_ARGON2_P_COST=1` for the production profile.

| Bench | Metric | Target | Notes |
| --- | --- | --- | --- |
| `argon2_calibration` | verify time | 0.5-1.0 s | Production profile m=19456 t=2 p=1 |
| `signin_password_bench` | sign-ins/sec | >= 60 | Bound by Argon2; scales by num_cpus / max concurrency |
| `signin_oidc_callback_bench` | ops/sec | >= 500 | Fixture decode and hot callback validation slice |
| `signin_saml_acs_bench` | ops/sec | >= 200 | Feature-gated XML fixture parse/fuzz slice |
| `session_resolve_bench` | ops/sec | >= 10000 | Warm LRU cache; primary acceptance gate |
| `session_resolve_bench_cold` | ops/sec | baseline only | Insert/get/evict cache-fill variant for trend tracking |

`scripts/check-bench-gate.sh <bench> <min-ops-per-sec>` parses Criterion
`estimates.json` and fails CI when the mean point estimate is below the named
threshold. The warm session resolver gate is the required bench signal.

## Environment Variables

| Name | Required | Default | Purpose | Validation |
| --- | --- | --- | --- | --- |
| `ZAGROSI_SECRETS_KEY` | Yes | None | Base64 32-byte AES key for the secrets envelope. | Must decode to exactly 32 bytes. |
| `ZAGROSI_VALKEY_URL` | Yes | None | Valkey connection for rate limits and lockouts. | Must parse as a URL. |
| `ZAGROSI_DATABASE_URL` | Runtime | None | PostgreSQL connection for binaries and tests. | Must be accepted by SQLx. |
| `ZAGROSI_NATS_URL` | Optional | Disabled | NATS session and email wakeup bus. | Empty disables bus-backed publishing. |
| `ZAGROSI_ARGON2_M_COST` | Optional | `19456` | Argon2 memory cost in KiB. | Must fit Argon2 params. |
| `ZAGROSI_ARGON2_T_COST` | Optional | `2` | Argon2 iteration count. | Must fit Argon2 params. |
| `ZAGROSI_ARGON2_P_COST` | Optional | `1` | Argon2 parallelism. | Must fit Argon2 params. |
| `ZAGROSI_ARGON2_MAX_CONCURRENCY` | Optional | `num_cpus` | Max concurrent blocking Argon2 jobs. | Values below 1 clamp to 1. |
| `ZAGROSI_PASSWORD_MIN_LENGTH` | Optional | `12` | Minimum password length. | Must be at least 12. |
| `ZAGROSI_PASSWORD_BREACHLIST_MODE` | Optional | `disabled` | HIBP breach-list mode. | One of `disabled`, `online`, `offline`. |
| `ZAGROSI_DNS_RESOLVERS` | Optional | `1.1.1.1,9.9.9.9` | DNSSEC resolvers for domain verification. | Minimum two resolvers. |
| `ZAGROSI_DNS_VERIFY_TTL_MINUTES` | Optional | `10` | Verified-domain cache TTL. | Must be nonzero. |
| `ZAGROSI_DNS_VERIFY_TIMEOUT_MS` | Optional | `5000` | Per-resolver DNS timeout. | Must be nonzero. |
| `ZAGROSI_DNS_CACHE_CAPACITY` | Optional | `10000` | Domain-verification cache size. | Must be nonzero. |
| `ZAGROSI_EMAIL_SMTP_URL` | Worker | None | SMTP URL for the email worker. | Must use an SMTP transport accepted by lettre. |
| `ZAGROSI_EMAIL_FROM` | Worker | None | Sender address for outbound email. | Must parse as a mailbox. |
| `ZAGROSI_PLATFORM_ADMIN_SUBJECTS` | Optional | Empty | Comma-separated human admin subject IDs. | Empty means service-token admin routes deny all. |
| `RUN_INTEGRATION` | Tests | Unset | Enables database/container integration tests. | Any non-empty value enables gated tests. |
| `ZAGROSI_RUN_FULL_SSO_E2E` | Tests | Unset | Enables full browser/provider SSO callback tests. | Any non-empty value enables gated tests. |

See `.env.example` for local placeholders.

## Standards Conformance Map

| Standard | Clause | Implementation | Test citation |
| --- | --- | --- | --- |
| OIDC Core 1.0 | Authorization Code flow | PKCE start and callback validation | `crates/zagrosi-identity/tests/oidc_flow.rs::oidc_authorization_code_pkce_s256_happy_path` |
| OIDC Core 1.0 | ID token audience, nonce, expiry | Negative callback tests | `crates/zagrosi-identity/tests/oidc_negative.rs` |
| RFC 7636 | PKCE S256 | OIDC start stores verifier and challenge | `crates/zagrosi-identity/tests/oidc_flow.rs::oidc_authorization_code_pkce_s256_happy_path` |
| RFC 9207 | Authorization server `iss` parameter | Callback rejects mismatched issuer | `crates/zagrosi-identity/tests/oidc_negative.rs::rejects_rfc9207_iss_mismatch` |
| OAuth 2.0 Security BCP | Refresh replay handling | Refresh chain replay revokes descendants | `crates/zagrosi-identity/tests/oidc_chain_invariants.rs::refresh_replay_revokes_chain` |
| OASIS SAML 2.0 Core | Bearer assertion and replay handling | ACS negative corpus and replay table | `crates/zagrosi-identity/tests/saml_negative_corpus.rs` |
| OASIS SAML Web SSO | SP-initiated redirect and ACS | SAML flow fixtures | `crates/zagrosi-identity/tests/saml_flow.rs` |
| RFC 7643 | SCIM user and group resources | Users and Groups route tests | `crates/zagrosi-identity/tests/scim_server.rs::create_user_then_get_round_trips_with_etag` |
| RFC 7644 | Filter grammar | Full comparison and boolean parser coverage | `crates/zagrosi-identity/tests/scim_filter_grammar.rs::every_comparison_operator_parses` |
| RFC 7644 | ETag and `If-Match` | Stale patch returns 412 | `crates/zagrosi-identity/tests/scim_server.rs::patch_with_stale_if_match_returns_412` |
| RFC 7644 | SCIM error envelope | Missing bearer and not-found tests | `crates/zagrosi-identity/tests/scim_server.rs::missing_bearer_returns_401` |
| NIST SP 800-63B | Password length policy and anti-enumeration | Password flow tests | `crates/zagrosi-identity/tests/password_flow.rs::password_reset_request_unknown_email_returns_ok` |
| OWASP Password Storage | Argon2id profile and calibration | Bench smoke and hasher tests | `crates/zagrosi-identity/tests/bench_smoke.rs::argon2_calibration_runs_one_iteration` |
| RFC 8176 | AMR claim propagation | OIDC ACR/AMR session assertion | `crates/zagrosi-identity/tests/oidc_flow.rs::oidc_acr_claim_persisted_to_session` |
| RFC 6585 | `Retry-After` on rate limit | Header rendering and Valkey lockout tests | `crates/zagrosi-identity/tests/rate_limit_valkey.rs::sliding_window_denies_after_budget_exhausted` |
| HTTP RateLimit Fields | `RateLimit-*` response headers | Rate-limit header unit coverage | `crates/zagrosi-identity/src/rate_limit/headers.rs` |

## Handoff Notes

### RBAC and audit

- Every multi-tenant table already carries `org_id`; repository helpers always
  anchor on the active organisation.
- `with_org_context(tx, org_id)` sets `app.current_org_id` inside the
  transaction so row-level-security predicates can read the current tenant.
- `Auditor`, `AuditEvent`, and `AuditEventV1` live in `zagrosi-core`.
  Identity wires `NoopAuditor` by default until a PostgreSQL auditor lands.
- `AuthContext` carries identity, active organisation, token class, AMR, ACR,
  expiry, and bearer-token scopes. RBAC roles and permissions remain outside
  that type.

### Admin UI

- Per-tenant SMTP can plug in behind `EmailTransport`.
- Account merge is intentionally not automatic; the UI should expose a reviewed
  merge flow for SSO email collisions.
- Email-outbox dead rows are visible through metrics; a manual retry endpoint is
  deferred.
- GDPR hard-purge should be a separate audited admin action.

### KMS

- The secrets envelope already carries `key_id`.
- Wrapped OIDC client secrets and SAML SP keys can be rewrapped without changing
  their database shape.
- Argon2 pepper adoption can use `password_hash_version` for migration.
