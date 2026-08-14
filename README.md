<!--
SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Varsel

Varsel is the software behind the [Erlang Ecosystem Foundation](https://erlef.org/)'s
CNA (CVE Numbering Authority): it manages the full lifecycle of CVE records for
the BEAM ecosystem — from vulnerability reports through reservation, drafting
and publication — and serves the public CVE, OSV, CWE and CAPEC data over HTML,
JSON, GraphQL and MCP.

## The name

*Varsel* is the Danish, Norwegian and Swedish word for "warning" or "advance
notice" — a vulnerability advisory in Norwegian is literally a
*sårbarhetsvarsel*. It nods to the Scandinavian roots of Erlang, which is named
after the Danish mathematician Agner Krarup Erlang and was created at Ericsson
in Sweden.

## What it does

- **CVE records** move through a single lifecycle (reserved → draft →
  publishing → published → pending update, or rejected), with every change
  tracked in an audit trail.
- **Vulnerability reports** can be submitted at `/report` (or via GraphQL and
  MCP) and are triaged by the CNA's points of contact; accepting a report
  opens a case.
- **Cases** collect the structured facts about a vulnerability: affected
  packages and their distribution channels, version events, references,
  credits, weaknesses and impacts. Affected version ranges are derived from
  the package's repository at render time rather than stored. Changes can be
  suggested as field-level proposals and discussed in comments; publishing a
  case renders it to CNA JSON and hands it to the CVE record.
- **OSV documents** are derived automatically from published CVE records.
- **CWE and CAPEC catalogs** are synced from MITRE into PostgreSQL on a weekly
  schedule and searchable via full-text search.
- **The public website** serves the CVE list and detail pages, statistics
  charts, the common-weaknesses overview, policy and process pages, and
  Atom/RSS feeds.

## Interfaces

- **HTML** — the public site, plus a management UI for authenticated users
  (GitHub or Hex.pm OAuth; `poc` and `supporter` roles).
- **JSON** — `GET /cves/index.json`, `/cves/:cve_id.json`, `/osv/all.json`
  and `/osv/:id.json`, without authentication.
- **GraphQL** — at `/gql`, login required: the published data plus the case,
  lifecycle, and user-management operations the caller's role allows.
- **MCP** — at `/mcp`, login required: the same data and case operations as
  tools for AI agents.

Both API surfaces authenticate with OAuth 2.1 access tokens or personal API
keys (managed at `/settings/tokens`); see
[cna.erlef.org/api-access](https://cna.erlef.org/api-access).

## Agent skills

This repo is also a Claude Code plugin (`varsel-poc`) bundling skills for CNA
points of contact who file CVEs with a local agent driving the MCP. See
[`skills/README.md`](skills/README.md) for the skill list and installation:

```
/plugin marketplace add erlef-cna/varsel
/plugin install varsel-poc@varsel
```

## Technology

Elixir and Phoenix (LiveView) with the [Ash](https://ash-hq.org/) framework on
PostgreSQL. Background work (OSV derivation, catalog syncs, notifications)
runs on Oban.

## Development

The development environment is managed with [devenv](https://devenv.sh/) as a
Nix flake:

```shell
nix develop --no-pure-eval
devenv up        # starts PostgreSQL
mix setup        # installs dependencies, creates and migrates the database
mix phx.server
```

The application is then available at [`localhost:4000`](http://localhost:4000).
Run `mix precommit` before committing; it formats, lints and runs the test
suite.

Signing in creates an account with no role. To give yourself the POC role,
open [AshAdmin](http://localhost:4000/dev/admin), find your user and set
`role` to `poc`. From an `iex -S mix phx.server` session instead:

```elixir
Varsel.Accounts.User
|> Ash.get!("<user-id>", authorize?: false)
|> Ash.update!(%{role: :poc}, action: :set_role, authorize?: false)
```

## Deployment

Releases are deployed to [Fly.io](https://fly.io/) by the GitHub Actions
release workflow: the production container image is built with Nix
(`nix/container.nix`), pushed with an SBOM and build attestations, and rolled
out — pushes to `main` deploy to the test environment, `v*` tags to
production. All runtime configuration lives in GitHub environment secrets and
variables.

A fresh deployment has no POC, and registration grants no role — setting one
otherwise requires an actor who is already a POC. Sign in once to create the
account, then promote it from a shell on the release:

```shell
bin/promote-to-poc <user-id>
```

That user can then set everyone else's role from the app.

## License

Apache-2.0. The repository follows the [REUSE](https://reuse.software/)
specification; see `LICENSES/` for all licenses involved.
