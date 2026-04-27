<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-006: Use Ash Oban for background and periodic jobs

**Status**: Accepted

## Context

The application requires periodic tasks (GitHub polling, IMAP polling, CVE pool
top-up, SLA enforcement) and triggered async tasks (email sending, MITRE
publication). These need reliable at-least-once execution, retries, and
observability.

## Decision

Use **Ash Oban** (the Ash extension wrapping Oban) for all background and periodic
jobs. Periodic jobs are declared with cron schedules in the Oban configuration.
Triggered jobs are enqueued via Ash actions where appropriate (e.g., the `publish`
action enqueues `PublishToCveServices`).

## Consequences

- Jobs have reliable at-least-once delivery with configurable retry policies
- Ash Oban integrates job definitions directly into Ash resources where it makes
  sense
- Oban's web dashboard (Oban Web) can be used for job monitoring
- Requires a dedicated `oban_jobs` PostgreSQL table (managed by Oban migrations)
