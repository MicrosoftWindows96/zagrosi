<div align="center">

# Zagrosi

**One open-source, self-hosted, AI-native platform for project management, issue tracking, and incident response.**

[![License: AGPLv3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status)
[![Backend: Rust](https://img.shields.io/badge/backend-Rust-orange.svg)](#stack)
[![Frontend: React](https://img.shields.io/badge/frontend-React-61dafb.svg)](#stack)
[![MCP Spec](https://img.shields.io/badge/MCP-2025--11--25-purple.svg)](#use-from-your-ai-editor)

</div>

---

> Zagrosi unifies the work that today is fractured across ClickUp, Jira, and incident.io into a single platform you can run yourself. Action items from a postmortem land in the same backlog as your sprint work. Issue severity drives on-call paging. Every surface is reachable from your AI editor through a first-party MCP server.
>
> **One platform. One source of truth. Zero per-seat fees.**

> 🚧 **Pre-alpha.** Designing in public. Not yet usable. ⭐ Star to follow along.

---

## Why Zagrosi

The modern engineering org runs three siloed tools to do one connected job:

| Tool category | Examples | What it owns |
|---------------|----------|--------------|
| Project management | ClickUp, Asana, Linear | Day-to-day tasks, projects, docs |
| Issue tracking | Jira, Shortcut | Sprints, epics, agile workflow |
| Incident response | incident.io, PagerDuty, FireHydrant | On-call, response, postmortems |

Each charges per seat. Each owns a slice of the same context. The action items born from a postmortem in tool C have to be retyped into tool A so they actually get worked. The status of a customer-impacting bug lives in tool B, but its incident timeline lives in tool C. There is no shared identity, no shared permissions, no shared search.

**And none of them speak fluently to AI editors.**

### Four coherent surfaces, one platform

<table>
<tr>
<td width="25%" valign="top">

#### 📋 Tasks
Work management with custom fields, multiple views (list / board / calendar / gantt), nested hierarchies, dependencies.

</td>
<td width="25%" valign="top">

#### 🔄 Issues
Agile workflow on top of tasks: sprints, epics, story points, kanban / scrum boards, JQL-style filtering.

</td>
<td width="25%" valign="top">

#### 🚨 Incidents
Severity-driven response with on-call schedules, escalation policies, runbooks, status pages, and postmortems.

</td>
<td width="25%" valign="top">

#### 🤖 AI-Native
Every surface as MCP tools, resources, and prompts. Declare incidents from Claude Code. Page on-call from Codex.

</td>
</tr>
</table>

All four share users, permissions, search, comments, audit log, and integrations. **First-class Slack and Microsoft Teams bridges** ship in-box: slash commands, auto-created incident channels, threaded action items, on-call paging, and notification routing, both directions. Self-hosted by default. AGPLv3 so it stays that way.

---

## Stack

| Layer | Choice |
|-------|--------|
| Backend | **Rust**: axum, tokio, sqlx |
| Frontend | **React + TypeScript**: Vite, TanStack Router/Query, Tailwind |
| Database | **PostgreSQL 18**: row-level security for multi-tenancy |
| Event bus | **NATS JetStream**: realtime, event sourcing, durable streams |
| Cache | **Valkey**: BSD-licensed Redis fork, OSI-approved (Redis Inc. relicensed to non-OSS in 2024) |
| Search | **Tantivy**: embedded, no Elasticsearch dependency |
| MCP server | **[rmcp](https://crates.io/crates/rmcp)** v1.5+: stdio + Streamable HTTP, MCP spec 2025-11-25 |
| Auth | Built-in email/password **+** OIDC / SAML SSO |
| Deploy | Docker Compose (single-node) **+** Helm chart (Kubernetes) |
| License | **AGPLv3** |

---

## Architecture

```
┌──────────────────────┐  ┌──────────────────────────────────────────┐
│    React Web App     │  │  AI editors: Claude Code, Codex CLI,     │
│                      │  │  Cursor, Zed, Claude Desktop             │
└──────────┬───────────┘  └──────────────────────┬───────────────────┘
           │ HTTPS + WS                          │ MCP (stdio / HTTP)
           ▼                                     ▼
┌──────────────────────────────┐    ┌─────────────────────────────┐
│      API Gateway (axum)      │◄──►│     zagrosi-mcp (rmcp)      │
│    REST + WS, NATS bridge    │    │ tools / resources / prompts │
└──────────────┬───────────────┘    └─────────────────────────────┘
               │
               │  Bounded-context Rust crates routed via NATS JetStream:
               │  identity, RBAC, work-item core, tasks, agile,
               │  incidents, alerts, oncall, docs, chat, postmortems...
               │
    ┌──────────┼──────────┐
    ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐
│Postgres│ │NATS JS │ │ Valkey │
└────────┘ └────────┘ └────────┘
```

Each bounded context is its own Rust crate inside a Cargo workspace. Cross-service calls go through NATS request/reply or shared Postgres tables, never direct HTTP. The MCP server is a thin translator from MCP primitives to api-gateway REST calls; same auth, same permission model, same audit log as the web UI.

---

## Roadmap

A solo build. Dates aspirational, not commitments. The product track and AI-Native track ship in parallel; every product phase lights up matching MCP capabilities.

| Phase | Status | Product | AI-Native (MCP + plugins) | Target |
|:-----:|:------:|---------|---------------------------|:------:|
| **0** | 📋 Planned | Foundation: monorepo, CI, identity, RBAC, multi-tenant, Docker/Helm | `zagrosi-mcp` skeleton (rmcp, stdio + HTTP, auth handshake) | ~2 mo |
| **1** | 📋 Planned | Tasks: work items, custom fields, list / board / calendar views | MCP v0.1: `create_task`, `list_tasks`, `update_task`, `task://<id>` resource | ~5 mo |
| **2** | 📋 Planned | Agile: sprints, epics, scrum / kanban boards, story points | MCP v0.2: sprint / board tools + `sprint_planning` prompt | ~7 mo |
| **3** | 🎯 **MVP** | Incidents: severity, on-call, escalation, runbooks | MCP v0.3: `declare_incident`, `page_oncall`, `ack_incident`, `incident_kickoff` prompt | ~10 mo |
| **4** | 📋 Planned | Docs: wiki with Yjs realtime collab | MCP v0.4: doc resources, full-text search tool | ~12 mo |
| **5** | 📋 Planned | Chat + notifications | n/a | ~14 mo |
| **6** | 📋 Planned | Postmortems: timeline, action items → tasks, analytics | MCP v0.5: timeline resource + `postmortem_template` prompt | ~16 mo |
| **7** | ♾️ Ongoing | Integrations marketplace (WASM plugin runtime), mobile, polish | Cursor extension, Zed plugin, Codex skill marketplace listing | ongoing |

Open issues for ideas, complaints, prior art.

---

## Quick start

### Self-host

> 🚧 **TBC**: installation instructions will be published once **Phase 0** ships.

### Use from your AI editor

> 🚧 **TBC**: `zagrosi-mcp` distribution (Cargo, Docker, prebuilt binaries) and per-client config snippets (Claude Code, Claude Desktop, Codex CLI, Cursor, Zed, Continue.dev) will be published with **MCP v0.1 (Phase 1)**.

### Use as a Claude Code plugin

> 🚧 **TBC**: slash commands (`/zag-incident`, `/zag-sprint`, `/zag-task`, `/zag-postmortem`) and a guided skill on top of the MCP tools will be published alongside **MCP v0.3 (Phase 3)**.

---

## How Zagrosi compares

| Feature | Zagrosi | ClickUp + Jira + incident.io |
|---------|:-------:|:----------------------------:|
| Self-hosted | ✅ Always | ❌ SaaS only |
| Open source | ✅ AGPLv3 | ❌ Proprietary |
| Unified data model | ✅ Tasks ↔ issues ↔ incidents linked at the DB | ❌ Three databases, three APIs, three webhooks |
| Single permission model | ✅ One RBAC across all surfaces | ❌ Three separate RBAC systems |
| MCP / AI-native | ✅ First-party MCP server | ❌ None ship MCP today |
| Per-seat pricing | 🆓 Zero | 💰 ~$30 to $80 / user / month combined |
| Vendor lock-in | 🆓 Run anywhere | 🔒 Triple lock-in |

---

## Contributing

This is currently a solo project in early design. The fastest way to help right now:

- ⭐ **Star the repo**: signals interest
- 💬 **Open a Discussion**: share use cases, complaints about your current tools, or design feedback
- 🐛 **File issues** on the design notes once they land

Code contributions will open up after the foundation phase ships. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow: branch and commit conventions, code review checklist, testing requirements, and DCO sign-off.

---

## License

[**GNU Affero General Public License v3.0**](LICENSE)

Zagrosi is AGPLv3 by design. You can self-host it freely. If you modify it and offer it as a service, you must publish your changes. This keeps the project a true commons rather than fuel for someone else's closed-source SaaS.

---

<div align="center">

Zagrosi takes its name from the [Zagros mountains](https://en.wikipedia.org/wiki/Zagros_Mountains) that run through Kurdistan.

**Layered ridges, layered modules.**

</div>
