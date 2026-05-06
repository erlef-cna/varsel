<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-011: GitHub OAuth for user login; signed tokens for Case Contact access

**Status**: Accepted

## Context

The application has two distinct authentication needs:

1. **Internal users** (PoC and Supporters) — need a proper login with session
   management. The EEF team already uses GitHub, making GitHub OAuth a natural fit.
1. **Case Contacts** — external reporters or maintainers who need temporary, scoped
   read access to a specific case without creating an account.

## Decision

**Internal users**: Use **AshAuthentication** with the GitHub OAuth strategy. Users
log in via GitHub; their `github_id` and `github_handle` are stored on the `User`
resource. Roles (`poc`, `supporter`) are assigned manually by a PoC after first
login.

**Case Contacts**: Generate a signed, expiring `Phoenix.Token` that encodes the
`case_id`. The token is embedded in a link sent to the contact (e.g., via email).
Visiting `/c/:token` verifies the token and grants read-only access to that specific
case and its threads. No account is created.

**GitHub App connection (advisory access)**: A separate optional OAuth flow allows
users to connect a dedicated GitHub App (distinct from the login OAuth App) from
their `/settings` page. This grants the application permission to fetch GitHub
Security Advisories on behalf of that user. Scope: `security_events`. Tokens
are stored in `Accounts.GitHubAppToken`, encrypted via Ash Cloak (ADR-004). This
connection is independent of login. See ADR-018 for the full token lifecycle, refresh
strategy, and Oban job design.

## Consequences

- GitHub OAuth eliminates password management for internal users
- New internal users require a PoC to assign a role before they can do anything
  — this is intentional and prevents unauthorized access after first OAuth login
- Case Contact tokens can be revoked by rotating the signing secret or setting an
  explicit expiry; short expiry (e.g., 30 days) is recommended
- Case Contacts cannot take any write actions; the token grants read-only access
  enforced by Ash Policies
- The GitHub App connection is optional and per-user; users who have not connected
  will not have advisories fetched on their behalf
