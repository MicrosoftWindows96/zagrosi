<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Changelog

All notable changes to Zagrosi are documented in this file. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) workspace-wide (the Cargo and pnpm workspaces share a single version line).

## [Unreleased]

## [0.1.0] - 2026-05-08

### Added

#### Workspace and tooling

- Cargo workspace manifest with explicit member list and a pinned dependency table covering serde, thiserror, anyhow, tracing, OpenTelemetry, Prometheus metrics, figment, axum, tokio, plus testing crates and reserved dependencies for later work.
- Production-grade workspace lints: `forbid unsafe_code`, `deny unwrap_used`, deny print and dbg, warn on expect / panic / todo / unimplemented, plus pedantic / nursery / cargo lint groups with documented exceptions.
- `clippy.toml`, `deny.toml`, `commitlint.config.mjs` (locking the 19 Conventional Commits scopes), `rust-toolchain.toml` (Rust 1.91.0), and `.editorconfig`.
- Root `.gitignore` covering generated artefacts and gitignored internal planning files.
- `LICENSE` (AGPL-3.0-or-later text, verbatim).

#### Foundation library and apps

- `zagrosi-core` foundation library: `ZagrosiError` thiserror enum with boxed `figment::Error` configuration variant, layered `CoreConfig` loader (env plus optional TOML, env wins, unknown fields tolerated), and an `Observability` guard wrapping `tracing-subscriber`, optional OTLP HTTP/protobuf export, and an optional Prometheus admin server with cooperative drop-time shutdown.
- `apps/api-gateway` placeholder binary that loads `CoreConfig`, calls `Observability::init`, emits a single `tracing::info!` line, and exits zero. Verifies workspace dependency wiring against `zagrosi-core` and that the production-grade lint set passes against a real binary under `-D warnings`.
- Reserved app directories `apps/zagrosi-mcp`, `apps/worker`, `apps/web`, each containing a `.gitkeep`. Filesystem regression tests guard the `.gitkeep`-only contract and the absence of `apps/admin`.

#### JavaScript workspace

- `pnpm-workspace.yaml` with `apps/*`, `packages/*`, `plugins/*` globs and a populated default catalog covering React 19 plus types, TypeScript 6, Vite 8, Vitest 4, Zod 4, Tailwind 4, TanStack Router and Query, prettier, and `@types/node` 24.
- Root `package.json` (private, `packageManager` pinned to pnpm 11.0.8, `engines.node` pinned to Node 24, six no-op recursive scripts).
- `.npmrc` enforcing `engine-strict`, `strict-peer-dependencies`, and `auto-install-peers`.
- `pnpm-lock.yaml` generated under pnpm 11.0.8 so CI can run `pnpm install --frozen-lockfile` from day one.

#### Dev infrastructure

- Local-development Compose stack at `deploy/docker/compose.yaml`: PostgreSQL 18, Valkey 9, NATS 2.14, all bound to `127.0.0.1` only with healthchecks and named volumes. Project name is explicit (`name: zagrosi`).
- Production-grade Valkey configuration at `infra/valkey/valkey.conf` (AOF appendfsync `everysec`, RDB save points, `allkeys-lru` eviction, slowlog).
- `infra/postgres/init/.gitkeep` reserves the directory bind-mounted at `/docker-entrypoint-initdb.d`.
- `.env.example` with the literal `changeme-strong-password-required` placeholder so contributors cannot accidentally ship the default password.
- `scripts/smoke-compose.sh` (mode `100755`) brings the dev stack up, polls health via `docker inspect`, runs sanity probes routed through a `probe` helper that dumps diagnostics on failure, and tears down via a `trap cleanup EXIT`. Self-contained env so CI can invoke it without a checked-in `.env`.

#### Helm chart

- Helm chart skeleton at `deploy/helm/`: empty-by-default `Chart.yaml` (apiVersion v2, kubeVersion `>=1.30.0`, dependencies present and empty), `values.yaml` with every component toggle disabled, Bitnami-style `templates/_helpers.tpl` (selector labels exclude `app.kubernetes.io/version` for immutability), and a `.helmignore` covering VCS / editor / OS / `.github/` / `ci/` / sensitive credential patterns.

#### CI

- GitHub Actions workflows at `.github/workflows/`: `rust.yml` (eight jobs covering fmt, dotenv lint, clippy, test, summary, deny, sbom via `taiki-e/install-action` for prebuilt cargo-cyclonedx, and compose smoke), `web.yml` (pnpm lint / typecheck / test with explicit pnpm version pin), `helm-lint.yml` (chart-testing-action with explicit ct version pin), `dco.yml` (pure-shell Signed-off-by trailer check with no third-party action), and `commitlint.yml` (wagoid/commitlint-github-action with explicit `configFile`). Every action `uses:` reference is pinned to a 40-character SHA. Every workflow declares minimal `permissions:`, a `concurrency:` block (`cancel-in-progress` only on PR events), and `timeout-minutes:` per job.
- `.github/branch-protection.json` documenting the modern Rulesets API payload for `main`: thirteen required status checks, `enforcement: active`, `bypass_actors: []` (administrators not exempt), and rules covering deletion, non-fast-forward, required linear history, and pull request review settings. Sidecar `.github/branch-protection.json.LICENSE` carries the SPDX header per the REUSE specification.

#### Repo hygiene and community-health files

- GitHub Issue Forms at `.github/ISSUE_TEMPLATE/`: `bug.yml` (with severity dropdown), `feature.yml`, `design-feedback.yml` (with area dropdown drawn from the 19 Conventional Commits scopes), and `config.yml` (blank issues disabled, two contact links).
- `.github/PULL_REQUEST_TEMPLATE.md` with six sections: Summary, Linked issue, Type of change (eight prefixes), Scope (nineteen entries), Test plan, and Checklist (five items: DCO, Conventional Commits, status checks, writing standards with a CONTRIBUTING.md link, no new dependencies without reason).
- `CODE_OF_CONDUCT.md`: verbatim Contributor Covenant 2.1 with `[INSERT CONTACT METHOD]` substituted to `conduct@zagrosi.com`.
- `SECURITY.md`: vulnerability reporting via `security@zagrosi.com`, 90-day coordinated-disclosure window, receipt acknowledged within five business days with a 72-hour target, and explicit scope including dev infrastructure and CI configuration.

#### Public-facing documentation

- `README.md`: project overview, surfaces summary, stack table (PostgreSQL 18, Valkey 9, NATS 2.14), architecture diagram, comparison table.
- `CONTRIBUTING.md`: contributor onboarding, branch-naming regex, Conventional Commits scopes, code-review checklist, testing requirements, accessibility, and code-style sections. Verified prose-style clean (no em-dashes, no en-dashes, no AI-tell phrases) at the close of the foundation phase.
- `documentation/governance.md`: nine-section governance manual covering branch protection, release cadence, issue triage, maintainers, voting, license posture, Code of Conduct enforcement, security disclosure, and trademark. Includes release tooling, drift-detection automation outline, voting worked examples, Code of Conduct outcome catalogue, security GitHub-Temporary-Private-Fork mechanism, supported-versions transition matrix, and trademark worked examples.
- `documentation/CHANGELOG.md`: this file (Keep a Changelog 1.1.0 format).

[Unreleased]: https://github.com/zagrosi-code/zagrosi/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zagrosi-code/zagrosi/releases/tag/v0.1.0
