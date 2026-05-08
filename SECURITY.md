<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Security policy

## Reporting a vulnerability

If you discover a vulnerability in Zagrosi, please email `security@zagrosi.com` with a description of the issue, reproduction steps, and an impact assessment. Do not open a public GitHub issue for security matters.

GitHub Security Advisories are an alternative private disclosure channel; reporters who prefer that route can request it in the initial email.

## Supported versions

Formal supported-versions tracking begins with Phase 3 of the project roadmap. Until then, security fixes land directly on the `main` branch and are documented in `documentation/CHANGELOG.md`.

| Version | Supported |
|---------|-----------|
| `main`  | Yes (until Phase 3) |

## Coordinated disclosure

Standard 90-day disclosure window from the date of the initial report to the date of public disclosure. Receipt is acknowledged within five business days, with a target of 72 hours. Once a fix lands, GitHub Security Advisories are used to issue CVEs.

## Recognition

Reporters may opt in to acknowledgement in the published advisory or in the relevant `CHANGELOG.md` entry. Anonymity is honoured on request.

## Scope

In scope:

- Source code in this repository.
- Dev-infrastructure manifests under `deploy/` and `infra/`.
- The Helm chart under `deploy/helm/`.
- The CI configuration under `.github/`.

Out of scope:

- Third-party dependencies; report those upstream.
- Self-hosted instances of Zagrosi run by third parties; report those to the operator.
- Social engineering of project maintainers.
