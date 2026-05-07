# Contributing to Zagrosi

Thank you for contributing to Zagrosi. This guide covers the workflow and standards for all contributions.

> **Note (pre-alpha):** Zagrosi is currently a solo project in early design. Most code-level contribution paths below are aspirational — they describe the standard contributors will be held to once the foundation phase ships. Until then, the most useful contributions are issues, discussions, and design feedback.

## Quick Start

1. See [documentation/onboarding.md](documentation/onboarding.md) for local development setup (coming during Phase 0)
2. Create a feature branch from `main`
3. Make your changes following the conventions below
4. Open a pull request using the PR template

## Developer Certificate of Origin (DCO)

Zagrosi is licensed under AGPLv3. To keep the licensing chain clean, every commit must be signed off under the [Developer Certificate of Origin](https://developercertificate.org/). Sign off automatically with:

```bash
git commit -s -m "feat(tasks): add custom field validation"
```

This appends a `Signed-off-by:` trailer asserting that you have the right to contribute the code under AGPLv3.

## Main Branch is Protected

The `main` branch is permanently protected. Direct pushes are blocked. All changes — including documentation, dependency bumps, and one-line fixes — must land via pull request from a feature branch.

Protection rules enforced on `main`:

- Linear history required (no merge commits from outside PRs)
- Pull request required before merging
- Conventional Commits subject required on the merge commit
- DCO sign-off required on every commit
- All status checks (Rust fmt / clippy / test, web lint / typecheck / test, MCP conformance) must pass
- Force-push and deletion blocked
- Administrators are not exempt

If you find yourself wanting to push directly to `main`, the answer is always "open a PR" — even for typo fixes.

## Branch Naming

All branches must follow this pattern:

```
^(feature|fix|hotfix|docs|chore|refactor|test|perf|ci)\/[a-z0-9]+-[a-z0-9-]+$
```

Examples:
- `feature/zg-42-task-custom-fields`
- `fix/zg-108-mcp-stdio-handshake`
- `docs/zg-200-adr-multi-tenant`
- `hotfix/zg-99-rls-bypass`
- `refactor/zg-150-incident-event-sourcing`

The numeric prefix matches the GitHub issue ID.

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/). Every commit message must start with a type prefix:

| Prefix | Use |
|--------|-----|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `docs:` | Documentation only |
| `chore:` | Maintenance, dependencies |
| `refactor:` | Code restructuring (no behaviour change) |
| `test:` | Adding or updating tests |
| `perf:` | Performance improvement |
| `ci:` | CI/CD pipeline changes |

Include a scope when helpful, scoped to the bounded context or app:

```
feat(tasks): add custom field validation
fix(mcp): handle stdio EOF cleanly
refactor(incidents): switch timeline to event sourcing
chore(deps): bump rmcp to 1.6
```

Allowed scopes: `identity`, `workspaces`, `tasks`, `agile`, `docs`, `chat`, `incidents`, `oncall`, `postmortems`, `search`, `notifications`, `scheduler`, `gateway`, `web`, `mcp`, `helm`, `compose`, `ci`, `deps`.

## Pull Request Process

1. Create a branch following the naming convention
2. Make your changes with signed-off conventional commits
3. Ensure all checks pass locally:
   ```bash
   # Rust
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --all-features

   # Web
   pnpm lint
   pnpm typecheck
   pnpm test
   ```
4. Push your branch and open a PR using the template
5. Request review from at least one maintainer (until the team grows, this means a self-review walkthrough recorded in the PR description)
6. Address review feedback
7. Merge using **merge commits** (not squash) to preserve individual commit history and DCO sign-offs

## Code Review Checklist

Reviewers should evaluate PRs against these categories:

### Correctness
- Logic is correct and handles edge cases
- No regressions to existing functionality
- Error handling is explicit (`?` propagates, `unwrap`/`expect` only in tests or proven-infallible paths)
- Async code does not block the runtime (no `std::sync::Mutex` held across `.await`, no blocking I/O on the runtime)

### Security
- No secrets or credentials in code or fixtures
- User input is validated at boundaries (`serde` + custom validators on the Rust side, Zod schemas on the web side)
- SQL injection, XSS, and CSRF protections maintained
- Postgres Row-Level Security policies cover any new tables before they ship — never disable RLS to "fix" a query
- MCP tools that mutate state require an authenticated session and respect the same RBAC as the REST endpoint they wrap
- AuthZ checks happen at the service layer, not the gateway

### Performance
- No N+1 queries in `sqlx` calls — prefer joins or batched `WHERE id = ANY($1)` patterns
- Large datasets are paginated (cursor-based by default, not offset)
- Hot paths use prepared queries; one-shot queries use `query!` macros for compile-time checking
- Client bundles are not unnecessarily increased; new dependencies justified in the PR description

### Testing
- New features have tests
- Edge cases are covered
- Tests are deterministic — no real time, no flaky timing dependencies; use `tokio::time::pause()` for async timers
- Database tests use the per-test transaction-rollback fixture, not a shared dirty database

### Readability
- Code is self-documenting with clear names
- Complex invariants have brief explanatory comments stating the *why*, not the *what*
- No dead code or commented-out blocks
- Public Rust items have rustdoc comments; exported TS types have JSDoc when not obvious from the name

### API Design
- REST conventions followed for HTTP endpoints; resource-oriented URLs, correct status codes
- `serde` request types are explicit structs, not `serde_json::Value` blobs
- MCP tool definitions specify clear input schemas and human-readable descriptions (clients render them to users)
- Response shapes are consistent with existing patterns in the same bounded context
- Breaking changes to MCP tools require a version bump in the tool name (e.g. `create_task_v2`)

## Testing Requirements

### Rust Unit & Integration Tests (`cargo test`)
- All new public functions, API handlers, and MCP tools must have tests
- Per-crate `tests/` for integration tests; in-module `#[cfg(test)]` for unit tests
- Database tests use `sqlx::test` with the test transaction fixture
- Run with `cargo test --all-features --workspace`
- Coverage with `cargo llvm-cov --workspace --html`

### Web Unit Tests (Vitest)
- All new utility functions and React hooks must have unit tests
- Run with `pnpm test` or `pnpm vitest run`
- Coverage with `pnpm test:coverage`

### End-to-End Tests (Playwright)
- Critical user flows must have E2E coverage
- Run with `pnpm test:e2e`

### MCP Conformance Tests
- Every new MCP tool must have a conformance test that drives it through `rmcp`'s test client
- Validates input schema, output shape, error mapping, and capability advertisement

### Performance Tests (Criterion)
- Hot paths (search, RLS-heavy queries, NATS dispatch) have criterion benchmarks
- Run with `cargo bench`
- Regressions over 10% require justification or a fix

## Accessibility

All UI changes must meet **WCAG 2.1 Level AA** compliance:

- Use semantic HTML elements (`<button>`, `<nav>`, `<main>`, not `<div>` with click handlers)
- Provide ARIA labels where semantic HTML is insufficient
- Ensure full keyboard navigation (no mouse-only interactions)
- Maintain minimum 4.5:1 contrast ratio for text
- Include visible focus indicators
- Test with screen reader (VoiceOver / NVDA)
- Realtime/collaborative surfaces (docs, chat) announce updates via ARIA live regions, not silent DOM mutations

## Code Style

### Rust
- `cargo fmt` is enforced on CI; no exceptions
- `cargo clippy --all-targets --all-features -- -D warnings` must pass — fix the warning, do not allow it
- No `unwrap()` or `expect()` outside tests and proven-infallible call sites; use `?` and typed errors (`thiserror` per crate, `anyhow` only at binary boundaries)
- No `unsafe` blocks without an accompanying `// SAFETY:` comment justifying every invariant
- Prefer `tracing` over `log` for instrumentation; structured fields, not formatted strings

### TypeScript
- **TypeScript strict mode** is enabled — follow it
- **ESLint** runs on CI — fix all warnings before pushing
- No `any` types — use proper type definitions or `unknown` with narrowing
- No `// @ts-ignore` or `// @ts-expect-error` — fix the underlying type issue
- No `eslint-disable` comments — fix the lint issue instead

### Database
- All schema changes go through `sqlx migrate add` — never edit a committed migration
- Every new table ships with its RLS policies in the same migration
- Index choices are justified in the migration's leading comment
