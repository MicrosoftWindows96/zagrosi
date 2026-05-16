<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Zagrosi Governance

This document records how Zagrosi is governed. It is the source of truth for branch protection, release cadence, issue triage, the maintainer roster, voting, license posture, Code of Conduct enforcement, security disclosure, and trademark policy. The companion files (`.github/branch-protection.json`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CONTRIBUTING.md`) carry operational detail; this document explains the intent.

Zagrosi is licensed under [GNU Affero General Public License v3.0 or later](../LICENSE). Every committed source file carries the SPDX identifier `AGPL-3.0-or-later`. The project enforces the Developer Certificate of Origin via `Signed-off-by:` trailers; there is no Contributor License Agreement.

The merging maintainer is responsible for keeping this document aligned with reality. Any pull request that touches `.github/branch-protection.json` or that changes the workflow set must update §1 in the same commit.

---

## 1. Branch protection

The `main` branch is permanently protected. The protection model uses GitHub's modern Rulesets API (not the legacy branch-protection API). The canonical payload lives at [`.github/branch-protection.json`](../.github/branch-protection.json); the prose below must remain in sync with that file. Drift between the two is a governance bug; the JSON is authoritative.

### Required status checks

Every pull request to the canonical repository's `main` branch must pass sixteen status checks before merge. All sixteen come from the project's own GitHub Actions workflows; the `cncf/dco2` GitHub App is supported as an additional layer when installed (its `DCO` context is not in the required-checks list, so the App is optional).

- `dco / dco` (the project's pure-shell Signed-off-by trailer check; lives at `.github/workflows/dco.yml`)
- `commitlint / lint`
- `rust / cargo fmt`
- `rust / dotenv lint`
- `rust / cargo clippy`
- `rust / rust test summary`
- `rust / cargo deny`
- `rust / cargo sbom`
- `rust / compose smoke`
- `rust / sso-integration`
- `rust / signin-bench`
- `rust / fuzz-smoke`
- `web / pnpm lint`
- `web / pnpm typecheck`
- `web / pnpm test`
- `helm / helm lint`

The `rust test summary` aggregator depends on the `cargo test` matrix; its presence in the required-checks list keeps the protection ruleset stable when matrix entries are added or removed.

### Settings enforced on `main`

- `enforcement: active`
- `required_linear_history: true`
- `non_fast_forward: true` (force pushes blocked)
- `deletion: true` (deletion blocked)
- `pull_request` rule:
  - `required_approving_review_count: 0` (solo maintainer; raises when the maintainer roster grows past one)
  - `dismiss_stale_reviews_on_push: true`
  - `require_code_owner_review: false`
  - `require_last_push_approval: false`
  - `required_review_thread_resolution: false`
- `bypass_actors: []` (administrators are not exempt)
- `strict_required_status_checks_policy: false`. The strict policy would force every PR to be re-tested against an updated `main`. Zagrosi prefers a faster merge path, with a separate post-merge run on `main` covering the integration check. The trade-off is that a PR can pass review against a slightly stale base; this is acceptable because all required checks must still pass, and the post-merge run on `main` catches any regression introduced by interaction with concurrent merges.

### Bootstrap and post-merge synchronisation

The first run of the workflows on the introducing PR registers the check names with GitHub. Until that registration completes, the ruleset cannot reference the real check names: it would block the very PR that introduces the workflows. The bootstrap pattern is:

1. Pre-create the ruleset with a placeholder pass-through check that already exists in the repository.
2. Open the PR that introduces the five workflows plus `branch-protection.json`.
3. Wait for the workflows to run on the PR (registering all twelve real check names).
4. Update the ruleset by running `gh api PUT /repos/<org>/<repo>/rulesets/<id> --input .github/branch-protection.json`.
5. Merge the PR.

There is no unprotected window: the placeholder ruleset is active throughout. The post-merge update swaps the placeholder for the real check list as a single atomic API call.

### Drift policy

When the prose in this section diverges from `.github/branch-protection.json`, the JSON wins. The merging maintainer is responsible for verifying alignment in every PR that touches either file. A maintainer may add automated drift detection at any time; until that automation lands, drift is caught by maintainer review.

### Drift-detection automation outline

The intended automation is a scheduled workflow that runs daily and on any PR that touches either file. Its responsibilities:

1. Fetch the live ruleset via `gh api GET /repos/<org>/<repo>/rulesets/<id>`.
2. Diff the live ruleset against the committed `.github/branch-protection.json` (modulo metadata fields that GitHub adds, such as `id`, `created_at`, `updated_at`, `node_id`).
3. On drift, fail the workflow and post a comment on the most recent open PR (or open an issue if no PR is open) listing the diff.
4. On no drift, exit zero silently.

The automation does not auto-correct. Drift is always a maintainer decision, because the JSON file may be intentionally lagging a transitional ruleset edit. Auto-correction risks reverting an in-progress maintainer change.

Until the automation lands, drift is caught by maintainer review during the PR that next touches either file.

### Why Rulesets and not the legacy branch-protection API

The legacy branch-protection API is feature-frozen. Modern features (multiple ref-name patterns, conditional rules, team-level bypass actors, etc.) are only available via Rulesets. Zagrosi adopts Rulesets from day one to avoid the migration cost later. The trade-off is that some older tooling (older `gh` versions, third-party GitHub clients, etc.) does not surface Rulesets; tooling must be reasonably modern.

---

## 2. Release cadence

Zagrosi follows Semantic Versioning workspace-wide. The Cargo workspace's `[workspace.package].version` and the pnpm workspace's `package.json` `version` field move together; both are bumped in the same release commit. Tags are formatted as `v<major>.<minor>.<patch>` and signed.

### Cadence

- Pre-1.0: monthly minor releases when there is meaningful work to ship; otherwise no release. A month with no shipping commits skips a release rather than tagging an empty bump.
- Patch releases are ad-hoc and primarily exist for security fixes. A security patch ships within five business days of the fix landing on `main`.
- Post-1.0: cadence is reviewed at the 1.0 mark. The default plan is quarterly minor releases with continued ad-hoc patches.

### Release tooling

The release procedure is currently manual. The maintainer:

1. Verifies that the workspace-wide tests, lints, and smoke tests are green on `main`.
2. Updates the version in `Cargo.toml` `[workspace.package].version` and in `package.json` to the next SemVer.
3. Moves the `[Unreleased]` body in `documentation/CHANGELOG.md` into a new `[<version>] - <date>` section, replacing the date with the merge date of the release commit.
4. Adds comparison-link footers to the CHANGELOG (`[Unreleased]: <repo>/compare/v<version>...HEAD` and `[<version>]: <repo>/releases/tag/v<version>`).
5. Opens a release pull request with a `chore(deps): release v<version>` subject, awaits CI green, merges the PR.
6. Tags the merge commit on `main` with `git tag -s v<version>` and pushes the tag.
7. Creates a GitHub release from the tag, copying the corresponding `[<version>]` CHANGELOG section into the release body.

The intent is to migrate to automated release tooling (a `cargo set-version` plus `pnpm version` script driven from a release-plz or changesets-equivalent workflow) once the project has more than one maintainer or once the manual procedure proves error-prone. Until then, the manual procedure with the seven steps above is the canonical release path.

### Changelog

Every tagged release has a corresponding entry in [`CHANGELOG.md`](./CHANGELOG.md). The format is Keep a Changelog 1.1.0; section headings are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, `Security`. The `[Unreleased]` section accumulates changes between releases; on tag the `[Unreleased]` body is moved to a new versioned section, the date is set to the merge date of the release commit, and `[Unreleased]` is reset to empty.

### Lockfile-conflict policy

`Cargo.lock` and `pnpm-lock.yaml` change frequently and conflict noisily on stacked dependency PRs. The policy:

- Serialise dependency-change PRs. Two PRs that both touch a lockfile must not be open against `main` simultaneously.
- Use minimal-diff updates. `cargo update -p <crate>` for a targeted Cargo bump; `pnpm update <package>` for a targeted pnpm bump. Avoid blanket `cargo update` or `pnpm update` runs in PRs that have any other change.
- Merge dependency PRs ahead of feature PRs that touch shared dependencies. The feature PR rebases on the merged dependency PR rather than the other way around; this keeps the dependency change isolated and reviewable.
- A dependency PR's body lists the bumped versions and any upstream advisory references. Reviewers approve based on diff plus advisory notes; rebuild-from-clean is the contributor's responsibility before opening the PR.

If a dependency PR sits unreviewed for more than seven days and the maintainer roster includes more than one active maintainer, any maintainer may merge it on a self-review walkthrough recorded in the PR description. The seven-day window covers the lazy-consensus default in §5. While the maintainer roster is a single person, the seven-day rule is vacuous (the sole maintainer cannot merge their own dependency PR through self-review hygiene); the policy operates as a forward-looking specification.

### Release-branch policy

Pre-1.0 has no release branches. Patches land on `main` and are tagged from `main`. Post-1.0, release branches are introduced if a pinned-version customer requests backports; the policy is documented at that point.

### Deprecation procedure

When a public API or configuration surface is to be removed:

1. The deprecation lands in a minor release with the `### Deprecated` CHANGELOG entry. The deprecated surface emits a runtime warning (Rust `tracing::warn!`, TypeScript `console.warn`) on first use per process.
2. The next minor release issues a follow-up `### Deprecated` reminder if the surface is still present.
3. The first major release after the initial deprecation removes the surface entirely; the removal lands as a `### Removed` CHANGELOG entry.

A surface introduced in pre-1.0 may be removed in a single minor release without going through this dance, because pre-1.0 explicitly permits breaking changes. The deprecation procedure is for post-1.0 stability commitments.

---

## 3. Issue triage

Issues are triaged weekly. The maintainer reviews every open issue carrying a `needs-triage` label, applies one priority and one type label, optionally an area label, removes `needs-triage`, and either assigns the issue, defers it to a backlog, or closes it as out of scope or duplicate.

### Required labels

- One priority label per issue: `priority/p0`, `priority/p1`, `priority/p2`, `priority/p3`.
- One type label per issue: `type/bug`, `type/feature`, `type/design-feedback`.
- Optional area label per issue, drawn from the 19 Conventional Commits scopes: `area/identity`, `area/workspaces`, `area/tasks`, `area/agile`, `area/docs`, `area/chat`, `area/incidents`, `area/oncall`, `area/postmortems`, `area/search`, `area/notifications`, `area/scheduler`, `area/gateway`, `area/web`, `area/mcp`, `area/helm`, `area/compose`, `area/ci`, `area/deps`.

### Severity-to-priority mapping

The bug-report issue template asks reporters to pick a severity. The maintainer maps severity to priority and to a response window during triage. The mapping is not automatic; reporters can be wrong and the maintainer's classification is authoritative.

| Severity | Priority | Response window |
|----------|----------|-----------------|
| critical | p0 | within 1 business day |
| high     | p1 | within 3 business days |
| medium   | p2 | within 2 weeks |
| low      | p3 | best effort |

A `priority/p0` issue takes precedence over scheduled work. A `priority/p1` issue is added to the active sprint or its equivalent. `priority/p2` and `priority/p3` go to a backlog reviewed at each weekly triage.

### Triage decision tree

For each issue carrying `needs-triage`:

1. Is the issue a duplicate? Close as duplicate with a link to the canonical issue.
2. Is the issue out of scope per the project roadmap? Close with a brief explanation and a pointer to a relevant alternative project if one exists.
3. Is the issue actionable today? Apply priority + type + area labels, remove `needs-triage`, optionally assign.
4. Is the issue actionable but blocked? Apply labels, remove `needs-triage`, add `blocked/<reason>` label and a comment naming the blocker.
5. Is the issue a feature request that requires design? Apply `type/design-feedback`, remove `needs-triage`, link to the design-feedback issue template if not already used.

### Stale-issue policy

Open issues with no activity for 60 days receive an automated comment asking whether the issue is still relevant. If there is no response within a further 30 days, the issue is closed with a `stale` label. Closed-stale issues can be reopened on request without prejudice; reopening resets the 60-day clock.

The 60-day window is project default. Individual issues may be marked `pinned/no-stale` by the maintainer when long-running discussion is expected (for example, an architecture decision under deliberation).

### Triage SLA on `needs-triage`

A `needs-triage` label that has not been removed within 14 days indicates a triage backlog. The maintainer either catches up at the next triage or escalates to ad-hoc triage during the week.

### Escalation

A reporter who believes their issue has been mistriaged may comment on the issue with a brief justification. The maintainer reconsiders at the next triage. If the reporter and the maintainer disagree on classification, the issue is brought to the wider maintainer roster (when one exists) for a vote per §5 on classification.

---

## 4. Maintainers

Zagrosi launches with a solo maintainer (the project owner). The maintainer's responsibilities:

- Review every pull request opened by external contributors.
- Triage issues weekly per §3.
- Cut releases per §2.
- Respond to security reports per §8 and to Code of Conduct reports per §7.
- Keep the governance documents in this file aligned with reality.

### Promotion path

A new maintainer is added on the proposal of an existing maintainer. The proposal is documented in a public issue and remains open for at least seven calendar days. Lazy consensus applies: silence after seven days equals approval. A vote per §5 is held only when there is explicit objection.

A new maintainer's first month is probationary. The probationary period is a normal-review-with-extra-attention period: the existing maintainer reviews every merge by the new maintainer for the first 30 calendar days. Graduation criteria: no rollback of a merged PR during the probationary period and at least three reviewed merges. Failure to meet either criterion extends the probationary period by another 30 days; repeated failure is grounds for demotion-by-vote per §5.

### Demotion path

A maintainer steps down voluntarily by opening a public issue and merging a CHANGELOG entry. A maintainer is removed by vote per §5 only when conduct or activity is in dispute. Removal-by-vote requires a documented pattern of behaviour and a 14-day discussion period before the vote opens.

A maintainer who is unreachable for 90 days is automatically marked emeritus; they retain credit but lose merge access until they choose to return. The emeritus transition does not require a vote.

### Off-boarding

A maintainer who steps down or is demoted has their merge access revoked, but their commits and contributions remain attributed. The CHANGELOG is updated with a `### Changed` entry noting the roster change. If the off-boarded maintainer is the security or Code of Conduct contact, the contact email is reassigned to the next maintainer in the roster and the corresponding files (`SECURITY.md`, `CODE_OF_CONDUCT.md`) are updated in the same release.

### Bus factor

While the project is solo, the bus factor is one. The project owner maintains an off-repository will-and-testament document specifying the trustees who would inherit the trademark and the canonical repository in the event of incapacity. The document is not published; its existence is recorded here so that future maintainers know to look for it.

---

## 5. Voting

Zagrosi defaults to lazy consensus for routine decisions. A formal vote is required only for the categories listed below.

### Decisions requiring a vote

- Adding or removing a maintainer.
- Changing the project license. AGPL-3.0-or-later is the project's permanent licence; a change requires a substantive AGPL-compatible substitute and a unanimous vote of active maintainers.
- Changing this governance document.
- Adding a runtime or build-time dependency on a non-OSI-approved license.
- Changing the project's official trademark policy (§9).

### Voting procedure

A vote is opened on the relevant GitHub issue or pull request. The proposer states the question and the options. Active maintainers vote with a comment containing `+1`, `-1`, or `0`. The voting period is seven calendar days. Quorum is a simple majority of active maintainers present at the close of the period. A `-1` is a veto only on license changes; for other categories a simple majority decides.

### Tie-break

If the vote ends with an equal number of `+1` and `-1`, the project owner casts the deciding vote. While the project is solo, every vote is functionally a unanimous decision by the sole maintainer; this section operates as a forward-looking specification.

### Lazy consensus

For decisions outside the categories above, silence after 72 hours equals approval. The 72-hour window starts from the moment the proposal is fully described in the relevant issue or pull request body (not from a comment thread). Any maintainer may extend the window by request; extensions are documented in the same thread.

### Worked example

A maintainer proposes adding `tracing-subscriber` as a workspace dependency. The category is "adding a runtime or build-time dependency": OSI-approved license (MIT-or-Apache-2.0) → no vote required, lazy consensus applies. The maintainer opens a PR with the dependency change, fully describes the addition in the PR body, and waits 72 hours. If no maintainer comments with concerns, the PR can merge after CI green.

A different maintainer proposes adding `bsl-licensed-library` as a runtime dependency. The category is "adding a runtime or build-time dependency on a non-OSI-approved license": vote required. The maintainer opens an issue first, waits seven days, collects votes. Simple majority decides; lazy approval does not apply.

---

## 6. License and CLA stance

Zagrosi is `AGPL-3.0-or-later`. The license is permanent; see §5 for the procedure to change it.

### DCO, not CLA

Contributors sign off on the Developer Certificate of Origin via a `Signed-off-by:` trailer on every commit. There is no Contributor License Agreement. The `Signed-off-by:` trailer asserts that the contributor has the right to contribute under AGPL-3.0-or-later. The `cncf/dco2` GitHub App enforces this on every PR; the project's own `dco / dco` workflow is an informational double-check.

### SPDX identifiers

Every committed source file (Rust, TypeScript, YAML, Markdown, shell, config) carries an SPDX identifier on the first line, in the appropriate comment syntax for the file type:

- `// SPDX-License-Identifier: AGPL-3.0-or-later` for Rust source files and TypeScript source files.
- `# SPDX-License-Identifier: AGPL-3.0-or-later` for YAML, TOML, shell scripts, and config files.
- `<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->` for Markdown and HTML.
- `{{/* SPDX-License-Identifier: AGPL-3.0-or-later */}}` for Helm templates.

The exemptions:

- **Verbatim third-party prose.** `CODE_OF_CONDUCT.md` is the Contributor Covenant 2.1 verbatim; it does not carry a project SPDX header. The third-party text's own copyright governs.
- **Strict-data files that cannot host comments.** `.github/branch-protection.json` is consumed by the GitHub Rulesets API which rejects unknown top-level keys; its SPDX header lives in the sidecar `.github/branch-protection.json.LICENSE` per the REUSE specification. Generated lockfiles (`Cargo.lock`, `pnpm-lock.yaml`) and other generated artefacts (cargo-cyclonedx SBOM output, coverage XML, etc.) are exempt as a class.
- **Empty placeholder files.** `.gitkeep` files are zero bytes by convention and carry no header.

### License-aware substitutions

Several commonly-used components have moved off OSI-approved licenses. Zagrosi prefers the OSI-approved substitute in every case:

- Valkey, not Redis (Redis Inc. relicensed Redis to non-OSS in 2024).
- OpenSearch, not Elasticsearch (Elastic relicensed Elasticsearch to non-OSS in 2021).
- OpenTofu, not Terraform (HashiCorp relicensed Terraform to BSL in 2023).

These substitutions are non-negotiable. A PR that introduces a non-OSI-approved license at the runtime or build-time surface fails `cargo deny check licenses` and triggers the vote in §5.

### Contributor copyright

Contributors retain copyright on their contributions. The DCO sign-off licenses the contribution under AGPL-3.0-or-later; it does not transfer copyright. A contributor who later wishes to use their own contribution under a different license is free to do so; the AGPLv3 grant to the project is irrevocable but does not preclude the contributor from licensing their own work under additional terms.

### Notes for contributors

- A first-time contributor reads `CONTRIBUTING.md`, configures git to sign off automatically (`git config commit.gpgsign true; git commit -s`), and follows the branch-naming and Conventional Commits rules.
- A contributor whose employer claims rights to the contribution must obtain employer permission before opening the PR. The project does not provide template language for this; the contributor's employer's open-source policy governs.
- A contributor who is a minor in their jurisdiction must obtain parental or guardian permission. The project does not request proof; the DCO sign-off is treated as good-faith assertion.

---

## 7. Code of Conduct enforcement

The Code of Conduct is the [Contributor Covenant 2.1](../CODE_OF_CONDUCT.md). The contact address is `conduct@zagrosi.com`.

### Reporting flow

A report arrives via email at `conduct@zagrosi.com`. The maintainer acknowledges receipt within 72 hours where possible, with a documented fallback of five business days when the maintainer is genuinely unavailable. The acknowledgement is private; it confirms receipt and outlines the next step (investigation, follow-up questions, or immediate action for clear-cut cases).

The maintainer investigates. The investigation is private to the parties involved and is not discussed publicly until the outcome is communicated. The maintainer may consult an external advisor; doing so does not change the maintainer's authority to decide the case.

The outcome is communicated to the reporter and to the subject of the report. The communication explains the decision and the action taken, if any. Outcomes range from no action (after investigation) through a private warning, a public warning, a temporary suspension from project spaces, or a permanent ban. The maintainer documents the outcome in a private record kept off the public repository.

### Outcome catalogue

- **No action.** The reported conduct does not violate the Code of Conduct, after investigation. The reporter is informed; the subject is informed only if the investigation surfaced their identity to them.
- **Private warning.** The conduct is borderline or a first occurrence. The subject is asked to refrain. No public record is created.
- **Public warning.** The conduct is a clear violation but not severe enough to warrant suspension. The subject is asked to refrain; a public record is created on the issue or PR where the conduct occurred, with the reporter's identity protected.
- **Temporary suspension.** The conduct is severe or repeated. The subject is suspended from project spaces (issues, PRs, Discussions) for a documented period. The suspension is announced publicly without naming the reporter.
- **Permanent ban.** The conduct is severe or unrepentantly repeated. The subject is permanently banned. The ban is announced publicly without naming the reporter.

### Appeals

The reporter or the subject may appeal an outcome by replying to the outcome email within 14 days. The appeal is reviewed by an additional maintainer if one exists, otherwise by the same maintainer with the appellant's case considered as written. An appeal extends the case timeline by up to 14 further days.

### Recusal

A maintainer recuses from any case involving themselves directly. When the project is solo, recusal means the case is referred to an external advisor of the project owner's choice; the choice is documented in the case record. When the project has multiple maintainers, the case is handled by the maintainers other than the recused individual.

### Worked example

A contributor opens an issue with a personal attack against a maintainer in the body. The targeted maintainer recuses. The remaining maintainers (or an external advisor while solo) review the issue. They determine the conduct is a clear violation and apply a public warning, deleting the offending text from the issue body and replacing it with a moderation note. The issue itself stays open for the legitimate technical content the contributor raised.

A contributor reports private harassment in Discussions. The maintainer investigates by reading the Discussions thread (which is private to the participants). The maintainer determines the conduct is severe and applies a temporary suspension. The suspension is announced publicly on a maintainer-authored Discussions post; the reporter is not named.

### Confidentiality

Reports, investigations, and outcomes are confidential. Public statements are limited to what is necessary for transparency (for example, the announcement of a permanent ban without naming the reporter). The project does not publish the contents of CoC reports.

---

## 8. Security disclosure

The security policy is documented in [`SECURITY.md`](../SECURITY.md). The contact address is `security@zagrosi.com`.

### Coordinated disclosure window

Standard 90-day window from the date of the initial report to the date of public disclosure. Receipt is acknowledged within five business days, with a target of 72 hours. Once a fix lands on `main`, GitHub Security Advisories issue the CVE and the fix is announced on the relevant release page and on the Discussions security board.

### Embargo and Temporary Private Forks

During the disclosure window the issue is embargoed. Discussion is limited to the maintainers, the reporter, and any explicitly added external advisors. The embargo prohibits public commits that hint at the fix.

The fix is developed in a GitHub Temporary Private Fork created from the GitHub Security Advisory. Temporary Private Forks preserve DCO sign-off enforcement and CI gating; they are not externally-hosted private repos. The Advisory's Temporary Private Fork is the canonical work surface during the disclosure window.

When the fix is ready:

1. The maintainer merges the fix into the Temporary Private Fork's branch.
2. The maintainer publishes the GitHub Security Advisory, which automatically pushes the fix branch to the public repository as a normal commit and tags the next patch release.
3. The advisory is announced on the Discussions security board.

### Recognition

Reporters may opt in to credit in the published advisory or in the relevant CHANGELOG entry. Anonymity is honoured on request. The default for unspecified reporters is named credit unless the reporter is identifiable as a research org with its own naming convention, in which case the org's preferred form is used.

### Out-of-scope reports

Reports concerning third-party dependencies are forwarded to the upstream project. Reports concerning self-hosted instances of Zagrosi run by third parties are referred to the operator. Reports concerning social engineering of project maintainers are documented but do not trigger the disclosure flow.

### Pre-Phase-3 caveat

Until the project ships Phase 3 of the public roadmap, formal supported-versions tracking does not exist. Security fixes land on `main` and are tagged at the next release. After Phase 3 the supported-versions table in `SECURITY.md` is filled in and the disclosure flow is updated to reference specific supported versions.

### Supported-versions transition matrix

The transition from "main only" to "formal supported versions" happens at Phase 3 of the public roadmap. The transition matrix:

| Stage | Coverage | CHANGELOG entries |
|-------|----------|-------------------|
| Pre-Phase 3 | `main` only | every fix on `main` |
| Phase 3 launch | `main` plus the most recent two minor releases | fix lands on `main` and is backported to supported minors |
| Post-Phase 3 maturity | `main` plus the most recent four minor releases | extended-support tier advertised on `SECURITY.md` |

The transition lands as a `### Changed` entry in the CHANGELOG and a `### Security` policy update in the same release.

### Worked example

A reporter emails `security@zagrosi.com` with a description of an authentication bypass in the API gateway. The maintainer acknowledges within 24 hours. The maintainer opens a GitHub Security Advisory and creates a Temporary Private Fork. The reporter is added as a collaborator on the Advisory. The maintainer develops the fix in the Temporary Private Fork over five days, with CI running against the private fork's branch. When the fix is ready and reviewed, the maintainer publishes the Advisory; the fix branch becomes a normal public commit and a patch release is tagged from the merge commit. The CHANGELOG `[<patch-version>]` entry includes a `### Security` bullet pointing to the published Advisory. The reporter is credited unless they opted out.

---

## 9. Trademark

The name `Zagrosi` and the project logo are owned by the project's original author. The trademark is not licensed under AGPL-3.0-or-later; it is held separately. The intent is to keep the name unambiguously associated with the canonical project while allowing the source code to be forked freely under the AGPLv3.

### Permitted uses

- Forking the project on GitHub for personal use, study, or contribution back to the canonical project.
- Publishing patches or pull requests against the canonical project under the project's name.
- Citing the project by name in research papers, blog posts, comparison tables, and similar editorial contexts.
- Distributing unmodified binaries of the project under the project's name.

### Restricted uses

- Distributing modified binaries of the project under the project's name without explicit written permission. A modified fork must rename its product before distribution. The fork retains the AGPLv3 source code rights but not the trademark.
- Hosting a paid service called `Zagrosi` or substantially named after Zagrosi without explicit written permission. Paid services running unmodified Zagrosi (genuine self-hosting on behalf of customers) are permitted; paid services running a modified fork must use a different name.
- Using the Zagrosi logo in commercial materials without explicit written permission. Editorial use of the logo (a comparison article, for example) is permitted under fair use.

### Logo license

The logo file is licensed CC BY-SA 4.0 separately from the source code. Attribution is to the canonical project's URL (`https://zagrosi.com`); modifications to the logo retain CC BY-SA 4.0.

### Enforcement

Trademark enforcement is handled directly by the project owner. Reports of trademark misuse can be sent to `trademark@zagrosi.com`. The project owner may choose to send a polite request first, escalate to a formal cease-and-desist, or pursue legal action depending on the case. The project does not publish trademark enforcement records.

### Worked examples

- A blog post compares Zagrosi to ClickUp and Jira and uses the Zagrosi name and logo. Permitted as editorial use.
- A fork at `github.com/example/zagrosi-fork` ships modified binaries on its GitHub Releases page and labels them "Zagrosi Modified Edition". Restricted: the fork must rename to something that does not include the canonical project's name (for example, `Zagrosi-derived` is unsafe, `OpenZagrosi` is unsafe, `MyTaskHub built on Zagrosi-derived code` is permitted because it does not present itself as Zagrosi).
- A SaaS company hosts the unmodified Zagrosi binaries for their customers and calls the service "ZagrosiCloud". Permitted in principle (genuine self-hosting on behalf of customers), but the trademark holder may request that the SaaS company use a clearly-derivative name to avoid confusion; written permission for the exact name is recommended.
- A research paper measures Zagrosi's MCP performance. Editorial use; permitted without permission. The paper credits the canonical project URL.

### Future custodianship

If the project's governance later moves to a foundation or other custodian, the trademark is transferred along with the governance. Until that transition, the trademark remains with the project owner. The transition would be announced as a `### Changed` CHANGELOG entry and would update §4 (Maintainers) and this section in the same release.

### Forks

A fork is not required to coordinate with the trademark holder for normal development work, contribution back to the canonical project, or personal use. A fork is required to coordinate when distributing under the canonical name, hosting a paid service named after the project, or using the logo commercially. The boundary between "fork for development" and "distribution under the canonical name" is the GitHub Release page or a similar public distribution surface.

---

## Cross-references

- [`.github/branch-protection.json`](../.github/branch-protection.json): canonical Rulesets API payload for `main`. §1 prose must match.
- [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md): Contributor Covenant 2.1 with project contact substitution. §7 governs enforcement.
- [`SECURITY.md`](../SECURITY.md): vulnerability reporting policy. §8 governs procedure.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md): contributor onboarding, branch-naming, Conventional Commits scopes, code review checklist, testing requirements, accessibility, code style.
- [`LICENSE`](../LICENSE): AGPL-3.0-or-later text.
- [`CHANGELOG.md`](./CHANGELOG.md): release history, Keep a Changelog 1.1.0 format.

This document supersedes any informal or undocumented governance practice. When informal practice diverges from this document, the document wins; informal practice is updated to match, or this document is updated by the procedure in §5.
