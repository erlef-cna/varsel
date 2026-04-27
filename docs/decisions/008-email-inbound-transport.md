<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-008: IMAP polling for inbound email

**Status**: Accepted

## Context

The CNA receives vulnerability reports and correspondence via email. Inbound emails
must be ingested reliably, matched to existing cases or used to create new ones,
and processed for GPG encryption/signatures.

## Decision

Use **IMAP polling** via an Oban periodic job (`PollImap`) running every 2 minutes.
The job connects to the CNA mailbox over IMAP, fetches unseen messages, parses them
(using the `mail` Elixir library), processes GPG, and creates or updates
`EmailMessage` records.

Outbound email is sent via **Swoosh** with a configurable SMTP adapter.

This approach requires no third-party email service dependency and works with any
standard mail server.

## Consequences

- Self-hosted, no dependency on Mailgun, Postmark, or similar services
- Up to 2-minute latency between email receipt and case creation
- IMAP credentials must be stored securely in env/secrets
- Large mailboxes or high volume may require pagination and state tracking
  (last-seen UID)
- Swoosh allows swapping the SMTP adapter without code changes (useful for different
  environments)
