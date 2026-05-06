<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-007: GitHub Advisory ingest via per-user GitHub App token polling

**Status**: Accepted

## Context

GitHub Security Advisories are a primary report channel for the EEF CNA. The system
needs to detect new advisories assigned to the CNA and ingest them as cases. Two
approaches were considered:

1. **GitHub App with webhooks**: Real-time push delivery. Requires a GitHub App
   to be installable on advisory repositories, which may not be supported for the
   private advisory workflow.
1. **Per-user GitHub App OAuth tokens with repository/org polling**: Each user
   authenticates a dedicated GitHub App from their `/settings` page. The app polls
   the GitHub repository and organisation security advisory APIs periodically using
   that user's token, for a user-configured list of watched targets.

## Decision

Use **per-user GitHub App OAuth tokens** with repository/org polling via
`GitHubWatchedTarget` records. Each authenticated user can connect a dedicated
GitHub App (separate from the login OAuth App, see ADR-011) from their `/settings`
page and register watched repositories or organisations. An AshOban trigger syncs
each watched target periodically using only that user's own token. See ADR-018 for
the full token lifecycle, data model, and ingest architecture.

This approach enables access to private advisories on repositories where the individual
user (not a shared credential) has been granted collaborator access, and makes
authorization explicit and auditable.

If GitHub App webhook support for security advisories becomes viable, it can be
added as a second ingest path alongside the polling path.

## Consequences

- Polling introduces latency between advisory creation and case creation
  (trigger runs every minute, skipping targets synced within 30 min)
- Per-user GitHub App tokens are stored encrypted in the DB via Ash Cloak (ADR-004);
  no shared bot credential is needed
- Advisory fetching only occurs for users who have connected the GitHub App
- A GitHub App webhook path can be added later as a `ReportChannel` strategy
  without significant rework
- Rate limits on the GitHub API must be respected; the polling interval should be
  tuned accordingly
