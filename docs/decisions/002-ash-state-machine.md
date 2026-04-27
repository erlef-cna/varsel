<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-002: Use ash_state_machine for Case status transitions

**Status**: Accepted

## Context

The `Case` resource has a multi-step lifecycle (under_review → accepted →
in_progress → ready_for_approval → approved → published, with rejection paths).
Invalid transitions must be prevented at the framework level, not enforced ad-hoc
in application code.

## Decision

Use `ash_state_machine` to model the Case status lifecycle. Each valid transition
is declared explicitly; the library raises an error on invalid transition attempts.
Each transition maps to a distinct Ash action, allowing per-transition Ash Policies.

## Consequences

- Invalid state transitions are impossible by construction
- Each transition action can have its own authorization policy and change set logic
- Ash Events automatically record state transitions as part of the audit log
- Adding new states or transitions requires updating the state machine declaration
