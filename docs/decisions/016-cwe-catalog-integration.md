<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-016: CWE Catalog Integration

**Status**: Accepted

## Context

The `cwe_capec` AI skill needs a local, searchable CWE (Common Weakness
Enumeration) catalog to suggest weakness IDs when classifying vulnerabilities.
The MITRE CWE catalog (~970 entries) is published as a ZIP-compressed XML file
at a stable URL and updated periodically.

## Decision

Introduce a `CveManagement.CWE` domain with two Ash resources:

### `CveManagement.CWE.Weakness`

Stores all CWE entries. Key design choices:

- **Primary key**: the integer `cwe_id` (e.g. 79), not a UUID.
- **`abstraction`**: `Ash.Type.Enum` with values
  `[:pillar, :class, :base, :variant, :compound]`.
- **`status`**: `Ash.Type.Enum` with values `[:stable, :draft, :incomplete, :deprecated]`.
- **`related_weaknesses`**: `{:array, CveManagement.CWE.RelatedWeakness}` — an
  embedded struct with a typed `Nature` enum rather than raw maps.
- **Full-text search**: a `tsvector GENERATED ALWAYS AS STORED` column
  (`search_vector`) combining name (weight A), description (weight B), and
  extended description / mitigations / consequences (weight C). Exposed via a
  `matches_query` calculation and a `:search` read action. The generated column
  and its GIN index are declared via `custom_statements` in the `postgres` block
  so migrations are fully auto-generated.
- **Sync action**: a generic action `:sync_cwe_catalog` that downloads the ZIP,
  unzips, parses, and bulk-upserts all weaknesses in batches of 200.
- **Scheduling**: AshOban scheduled actions — weekly (`0 5 * * 1`) and `@reboot`
  — so data is always current and pre-loaded on startup.

### `CveManagement.CWE.CweMetadata`

Singleton resource (string PK `"singleton"`, no timestamps) that stores the
`Last-Modified` HTTP header value from the last successful download. Used as
`If-Modified-Since` on subsequent requests to skip redundant downloads (MITRE
returns `Last-Modified` but no ETag).

### XML Parsing

Erlang's built-in `:xmerl_scan` is used (no extra dependency). Text content is
extracted recursively from all descendant `xmlText` nodes (the CWE XML wraps
content in `<xhtml:p>` and similar elements), with `List.to_string/1` applied to
each charlist value to handle Unicode codepoints correctly.

## Consequences

- No new mix dependencies — `:xmerl_scan` is part of the Erlang stdlib.
- The `cwe_sync` Oban queue (concurrency 1) must be configured.
- Re-syncing is safe and idempotent (upsert on primary key).
- Full-text search quality degrades only when MITRE restructures the XML schema,
  which is rare.
