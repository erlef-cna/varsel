<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-018: Per-user GitHub App OAuth for Advisory Fetching

**Status**: Accepted

## Context

ADR-007 specified a shared bot account (personal access token) for polling GitHub
and ingesting security advisories. That approach has two shortcomings:

1. A single PAT cannot access private advisories on repositories where individual
   team members (not the bot) have been granted collaborator access.
1. A shared credential makes authorization opaque — it is unclear which human actor
   authorized a given advisory fetch.

GitHub Apps support a proper OAuth flow that issues short-lived `access_token` +
`refresh_token` pairs (1-hour access tokens, refreshable for up to 6 months). This
enables per-user advisory fetching with explicit, auditable authorization.

This ADR replaces the shared bot account design in ADR-007 with a per-user GitHub
App OAuth flow. ADR-007 is **amended** (not superseded) to reference this decision.

## Decision

### GitHub App setup

A dedicated GitHub App (separate from the login OAuth App described in ADR-011) is
registered with the following permission:

- `security_events` — read private/unreleased GitHub Security Advisories

Users connect the app voluntarily from a `/settings` page. Connection is optional;
advisory fetching only occurs for users who have connected.

### Resource: `Accounts.GitHubAppToken`

One record per user (unique index on `user_id`).

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `id` | UUID | No | |
| `user_id` | UUID (FK) | No | References `User`; unique |
| `access_token` | string | Yes (Ash Cloak) | Current GitHub App access token |
| `refresh_token` | string | Yes (Ash Cloak) | Used to obtain new access tokens |
| `expires_at` | utc_datetime | No | Expiry of the current access token; stored plaintext for scheduling |
| `status` | enum: `valid`, `invalid` | No | `invalid` set on 401 or refresh failure |
| `inserted_at` | utc_datetime | No | |
| `updated_at` | utc_datetime | No | |

Actions:

- `:upsert_from_oauth` — stores or updates the token; an AshOban trigger schedules
  token refresh at `expires_at - 10 minutes`.
- `:mark_invalid` — sets `status: :invalid`; called on 401 from the advisory API or
  on refresh failure. The user sees the invalid status on `/settings`.
- `:refresh` — AshOban update action that POSTs the `refresh_token` to the GitHub
  token endpoint and upserts the new token pair; on failure calls `:mark_invalid`.

Policy:

- A user may only read or modify their **own** `GitHubAppToken`.
- No other role (including `poc`) may access another user's token.
- Oban jobs run with the owning user as the actor; they load only that user's token.

### Resource: `ReportChannels.GitHubWatchedTarget`

One record per user-configured watch (repository or organisation). Drives all
advisory sync jobs.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | UUID | |
| `user_id` | UUID (FK) | References `User` |
| `owner` | string | GitHub org or user name |
| `repo` | string (nullable) | Repository name; nil = org-level watch |
| `synced_at` | utc_datetime (nullable) | Set after each successful sync |
| `inserted_at` | utc_datetime | |
| `updated_at` | utc_datetime | |

Identity: `[:user_id, :owner, :repo]` (unique per user).

Actions:

- `:create` — accepts `owner`, `repo`, `user_id`; immediately enqueues a sync job
  via `run_oban_trigger(:sync)`.
- `:sync` — AshOban update action; loads the user's `GitHubAppToken`, calls
  `AdvisoryClient.fetch_repository_advisories/3` or
  `AdvisoryClient.fetch_org_advisories/2` depending on whether `repo` is set,
  ingests each advisory via `GitHubAdvisory.ingest_json!/2`, sets `synced_at`.
- `:destroy`

AshOban trigger on `:sync`:

```
where: is_nil(synced_at) or synced_at <= ago(30, :minute)
scheduler_cron: "* * * * *"
queue: :github_advisory_sync
```

Policy: users may only create/read/destroy their own watched targets.

### Resource: `ReportChannels.GitHubAdvisory`

Replaces `ReportChannels.GitHubReport`. All GitHub advisory fields are stored as
typed columns (no `raw_payload`). `ghsa_id` is the primary key.

Key attributes:

| Field | Type | Notes |
| --- | --- | --- |
| `ghsa_id` | string (PK) | GHSA identifier |
| `cve_id` | string (nullable) | |
| `summary` | string (max 1024) | |
| `description` | string (nullable, max 65535) | |
| `severity` | enum: `critical`, `high`, `medium`, `low` (nullable) | |
| `state` | enum: `published`, `closed`, `withdrawn`, `draft`, `triage` | |
| `url` | string | GitHub API URL |
| `html_url` | string | GitHub web URL |
| `author` | embedded `GitHubUser` (nullable) | `login`, `html_url`, `avatar_url` |
| `publisher` | embedded `GitHubUser` (nullable) | |
| `github_created_at` … `github_withdrawn_at` | utc_datetime (nullable) | GitHub timestamps |
| `vulnerabilities` | array of embedded `VulnerablePackage` (nullable) | |
| `cvss_severities` | embedded `CvssSeverities` (nullable) | holds `cvss_v3` and `cvss_v4` as `CveManagement.Types.CVSS` custom type |
| `identifiers` | array of embedded `Identifier` (nullable) | |
| `credits` | array of embedded `Credit` (nullable) | |
| `credits_detailed` | array of embedded `CreditDetailed` (nullable) | |
| `collaborating_users` | array of embedded `GitHubUser` (nullable) | |
| `collaborating_teams` | array of embedded `CollaboratingTeam` (nullable) | |
| `submission` | embedded `Submission` (nullable) | |
| `private_fork` | embedded `PrivateFork` (nullable) | |
| `processed_at` | utc_datetime (nullable) | set when a Case is created |
| `fetched_by_user_id` | UUID (FK) | |
| `case_id` | UUID (FK, nullable) | |
| `inserted_at`, `updated_at` | utc_datetime | |

Relationships:

- `belongs_to :fetched_by_user, User`
- `belongs_to :case, Cases.Case`
- `many_to_many :weaknesses, CWE.Weakness` via `GitHubAdvisoryWeakness` join table;
  populated from the `cwe_ids` field on ingest.

Actions:

- `:ingest_json` — create (upsert by `ghsa_id`); accepts `fetched_by_user_id` and
  `raw_data` map; uses `Changes.ParseJson` to map GitHub API fields to attributes.
- `:ingest_url` — create (upsert); accepts `fetched_by_user_id` and `url`; uses
  `Changes.FetchUrl` (fetches the URL with the user's token) then `Changes.ParseJson`.
- `:refresh` — update action; re-fetches from `url` using the user's token and
  upserts updated fields. AshOban trigger runs every 30 min for `draft`/`triage`
  advisories not updated within the last hour.
- `:read`, `:fetch_by_ghsa_id`

`Changes.ParseJson` maps GitHub API string-keyed JSON to typed Ash attributes.
`Changes.FetchUrl` loads the user's `GitHubAppToken` and calls
`AdvisoryClient.fetch_advisory/2`.

Policy:

| Actor | Permission |
| --- | --- |
| PoC | read all |
| Fetching user (`fetched_by_user_id`) | read |
| Collaborating user (login in `collaborating_users`) | read (via PostgreSQL `unnest` query on the JSONB column) |
| Case-assigned user | read (when `case_id` is set and user is assigned) |
| Ingest actions (`:ingest_json`, `:ingest_url`) | always authorized |

### OAuth callback flow

1. User clicks "Connect GitHub App" on `/settings`.
1. Redirect to GitHub OAuth authorization URL for the GitHub App.
1. GitHub redirects to `/auth/github_app/callback?code=...`.
1. Phoenix controller exchanges the code for `access_token`, `refresh_token`, and
   `expires_in` via the GitHub token endpoint.
1. Calls `GitHubAppToken.upsert_from_oauth`:
   a. Encrypts and upserts the token record.
   b. AshOban trigger schedules `:refresh` at `expires_at - 10 minutes`.
1. Redirects back to `/settings` with a success flash.

### Oban queues

`github_advisory_sync` queue (concurrency: 5) handles:

- `GitHubAppToken` `:refresh` trigger (token rotation)
- `GitHubWatchedTarget` `:sync` trigger (advisory fetch per watched target)
- `GitHubAdvisory` `:refresh` trigger (re-fetch individual advisories)

### Encryption

`access_token` and `refresh_token` are encrypted via Ash Cloak (AES), consistent
with ADR-004. `expires_at` is stored in plaintext because it is needed for scheduling
and contains no secret material.

## Consequences

- Advisory fetching is bounded to repositories each user has personally been granted
  access to, making authorization explicit and auditable.
- Users who have not connected the GitHub App will not have advisories fetched on
  their behalf.
- Token credentials (`access_token`, `refresh_token`) are encrypted at rest; a raw
  DB dump does not expose them.
- The `/settings` page must surface `GitHubAppToken.status` so users know if their
  connection is valid.
- The `github_advisory_sync` Oban queue must be added to the Oban configuration.
- The shared bot account PAT from ADR-007 is removed.
- The `:cvss` Erlang library is added as a Mix dependency for CVSS vector parsing
  and scoring via the `CveManagement.Types.CVSS` custom Ash type.
