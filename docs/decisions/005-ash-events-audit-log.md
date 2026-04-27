<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-005: Use Ash Events for audit logging

**Status**: Accepted

## Context

CVE case management requires a complete, tamper-evident audit trail: who changed
what, when, and from which state. This is important for compliance, dispute
resolution, and transparency within the CNA team.

## Decision

Use **Ash Events** to automatically record events for all significant Ash
actions (resource creates, updates, state transitions, approvals, publications).
Events are immutable append-only records. Custom events can be emitted for
non-resource operations (e.g., SLA breaches, email sends, AI skill runs).

## Consequences

- Every state transition and data change is automatically logged with actor,
  timestamp, and diff
- Events are queryable via Ash and can be surfaced in a case timeline view in the
  UI
- No additional audit logging code is needed in application logic
- Storage grows linearly with activity; event retention policy should be defined
