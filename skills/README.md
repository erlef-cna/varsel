<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Varsel POC plugin

A Claude Code **plugin** of skills for a Varsel CNA point-of-contact (POC) filing
CVEs through the **Varsel MCP** (`mcp__varsel__*` tools). The agent states the
vulnerability as facts on a **case** via field-level proposals; Varsel derives
version ranges, renders the CNA record, validates, and (on human approval)
pushes to MITRE.

The plugin manifest lives in [`.claude-plugin/`](../.claude-plugin) at the repo
root; the skills below are the plugin's payload.

## Installation

This repo doubles as a single-plugin marketplace. From Claude Code:

```
/plugin marketplace add erlef-cna/varsel
/plugin install varsel-poc@varsel
```

(Or point at a local checkout: `/plugin marketplace add /path/to/varsel`.)

### Prerequisite: the Varsel MCP

The skills assume the Varsel MCP server is already **installed and
authenticated**. They call `mcp__varsel__*` tools, so the server must be
connected and logged in (`/mcp`) with a Varsel API key or OAuth token before
running any skill — without it, the tools the skills invoke are unavailable.

See <https://cna.erlef.org/api-access#mcp> for how to connect and authenticate.

## Skills

| Skill | Purpose |
|-------|---------|
| `new-cve` | Orchestrator. Advisory → case proposals → derive → verify (stops review-ready). |
| `cvss` | Produce a CVSS v4.0 vector (Varsel derives the numeric score). |
| `find-cwe` | Pick a CWE from the MCP catalog (`search_weaknesses` / `get_weakness`). |
| `find-capec` | Pick a CAPEC — start from the CWE's `related_attack_patterns`, fall back to search. |
| `find-intro-commit` | Git archaeology to return the introducing commit SHA. |
| `verify` | Render the case preview, run the MCP validators, walk the convention checklist. |
| `summarize-cve` | Human-readable technical write-up from a case or published CVE. |

Each skill is invocable directly (e.g. `/new-cve`); `new-cve` calls the others
as sub-steps.

## What Varsel automates (and these skills therefore do not do)

- **Affected version ranges, CPEs, `cpeApplicability`, per-channel path scoping** — derived from commit-SHA facts. Presets (`otp` / `elixir` / `gleam`) prefill vendor/product/repo/CPE and channels.
- **Formatting, schema validation, cvelint, hex-package checks** — the `render_case_preview` and `validate_cve_record*` tools.
- **The MITRE push and OSV derivation** — the derived OSV records follow publish.

The agent can open a fresh draft case (`open_case`) and author proposals against
it, but CVE ID assignment, proposal acceptance, and publishing all happen in the
UI (a human) — the skills stop at a verified, review-ready state.

## Guardrails

- Every case change is a **proposal**; a human accepts it. The agent never self-approves.