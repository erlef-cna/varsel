<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-007: GitHub Advisory ingest via bot account notification polling

**Status**: Accepted (implementation TBD)

## Context

GitHub Security Advisories are a primary report channel for the EEF CNA. The system
needs to detect new advisories assigned to the CNA and ingest them as cases. Two
approaches exist:

1. **GitHub App with webhooks**: Real-time push delivery. Requires a GitHub App
   to be installable on advisory repositories, which may not be supported for the
   private advisory workflow.
1. **Bot user account with notification polling**: A dedicated GitHub bot account
   (e.g., `@erlef-cna-bot`) is added as a collaborator on relevant repositories
   or the CNA organization. The app polls the GitHub notifications API
   periodically.

## Decision

Implement the **bot account + notification polling** path as the initial approach,
since it is known to work with the GitHub advisory/private fork workflow. An Oban
periodic job (`PollGitHubNotifications`) polls the GitHub notifications API every
5 minutes for the bot account.

If GitHub App webhook support for security advisories becomes viable, it can be
added as a second ingest path without replacing the polling path.

## Consequences

- Polling introduces up to 5-minute latency between advisory creation and case
  creation
- Bot account credentials (personal access token) must be stored securely in
  env/secrets
- A GitHub App webhook path can be added later as a `ReportChannel` strategy
  without significant rework
- Rate limits on the GitHub API must be respected; the polling interval should be
  tuned accordingly
