<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-003: Use LangChain for Elixir + ash_ai for AI integration

**Status**: Accepted

## Context

Several CVE-building tasks benefit from AI assistance: triage, CVSS generation,
CWE/CAPEC determination, description writing, commit bisection, and patch
location. The system needs a way to run these as structured, auditable
operations against a configurable LLM backend.

## Decision

Use **LangChain for Elixir** as the primary LLM abstraction layer. Each AI skill
is a separate LangChain chain module, making skills independently testable and
replaceable. Use **ash_ai** for action-aware integration: ash_ai provides tool-call
scaffolding that exposes Ash actions as LLM tools, allowing skills to read and
update resources directly.

AI skill runs are persisted in the `AiSkillRun` resource for auditability. Users
always review AI output before it is saved to the CVE record.

## Consequences

- LangChain supports multiple LLM backends (Anthropic Claude, OpenAI, etc.)
  via a common API
- ash_ai reduces boilerplate for exposing Ash actions as LLM tools
- Each skill is independently mockable for deterministic tests (record/replay
  adapters)
- AI suggestions are never auto-saved; human review is required
- Model costs are incurred per skill invocation; `AiSkillRun` enables cost tracking
