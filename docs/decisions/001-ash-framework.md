<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-001: Use Ash Framework as the data and business logic layer

**Status**: Accepted

## Context

The application needs a consistent way to define resources, enforce authorization
policies, generate APIs, handle changesets, and integrate with background jobs,
encryption, events, and AI tooling. Plain Ecto covers the persistence layer but
leaves all of these concerns to application code.

## Decision

Use the Ash Framework (ash, ash_postgres, ash_phoenix) as the primary data and
business logic layer. All domain resources are defined as Ash resources. Ash
Policies are the single source of truth for authorization.

## Consequences

- All resources, actions, and policies are declared in a consistent, introspectable
  way
- Ash's extension ecosystem (GraphQL, Oban, Cloak, Events, StateMachine, AI)
  integrates seamlessly without additional glue code
- The learning curve is steeper than plain Ecto/Phoenix for contributors unfamiliar
  with Ash
- Ash 3.x is the target; breaking changes between major versions require migration
  effort
