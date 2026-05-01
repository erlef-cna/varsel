<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# ADR-017: CAPEC Catalog Integration

**Status**: Accepted

## Context

ADR-016 introduced local CWE data for AI-assisted CVE analysis. The planned
`cwe_capec` AI skill needs to take a CWE ID and identify relevant CAPEC
(Common Attack Pattern Enumeration and Classification) attack patterns — for
example, to surface attack methods an adversary could use to exploit a given
weakness.

MITRE publishes ~600+ CAPEC entries as a single XML file at a stable URL:
`https://capec.mitre.org/data/xml/capec_latest.xml`. The data is updated
infrequently but must be kept reasonably fresh. Storing it locally avoids
latency and rate-limit concerns during AI skill runs.

This ADR mirrors ADR-016 exactly, adapted for CAPEC's XML structure and a
few additional enum fields.

## Decision

Introduce a `CveManagement.CAPEC` domain with four Ash resources.

### `CveManagement.CAPEC.AttackPattern`

- Integer primary key `capec_id` (maps to the `ID` XML attribute).
- Attributes covering fields useful for AI analysis: `name`, `abstraction`,
  `status`, `description`, `extended_description`, `likelihood_of_attack`,
  `typical_severity`, `related_attack_patterns`, `related_weaknesses`,
  `prerequisites`, `mitigations`, `consequences`.
- Four enum types specific to CAPEC:
  - `Abstraction`: `[:meta, :standard, :detailed]` (3 levels vs CWE's 5)
  - `Status`: `[:draft, :stable, :deprecated]`
  - `Likelihood`: `[:high, :medium, :low]` (optional field)
  - `Severity`: `[:high, :medium, :low]` (optional field)
- `related_attack_pattern_relationships`: a `has_many` to
  `CveManagement.CAPEC.AttackPatternRelationship`, a proper join table with
  columns `source_capec_id`, `target_capec_id`, and a typed `Nature` enum.
  Self-referential FKs use `DEFERRABLE INITIALLY DEFERRED` (via
  `reference :target, deferrable: :initially`) so forward-referencing entries
  within the same bulk batch are accepted.
- `weaknesses`: a `many_to_many` to `CveManagement.CWE.Weakness` through
  `CveManagement.CAPEC.AttackPatternWeakness`, linking attack patterns to
  their relevant CWE IDs. Only weaknesses already present in the CWE catalog
  are linked (`on_no_match: :ignore`).
- Full-text search via a PostgreSQL `tsvector GENERATED ALWAYS AS ... STORED`
  column (`search_vector`), with a GIN index. Weights: name (A),
  description (B),
  extended_description/prerequisites/mitigations/consequences (C).
- Sync action downloads directly from
  `https://capec.mitre.org/data/xml/capec_latest.xml` (raw XML — no ZIP
  extraction needed, unlike the CWE catalog).
- Uses `If-Modified-Since` / `304 Not Modified` deduplication via
  `CapecMetadata`, identical to the CWE pattern.
- Scheduled via AshOban: weekly (Mon 5am UTC) + `@reboot`, on a dedicated
  `capec_sync` Oban queue (concurrency 1).
- Bulk upsert is wrapped in a single `Ash.transact/2` call so deferred FK
  constraints are checked only at transaction commit, allowing forward
  references within the same batch.
- The sync action requires CWE to be synced first — it asserts
  `[_] = Ash.read!(CweMetadata)` and raises if the CWE singleton is absent.

### `CveManagement.CAPEC.AttackPatternRelationship`

Join resource for directed attack-pattern-to-attack-pattern links,
corresponding to `<Related_Attack_Pattern>` XML entries. Composite primary
key: `(source_capec_id, target_capec_id, nature)`. The `target_capec_id` FK
is `DEFERRABLE INITIALLY DEFERRED`.

### `CveManagement.CAPEC.AttackPatternWeakness`

Join resource linking `AttackPattern` to `CWE.Weakness` via
`(capec_id, cwe_id)`. Populated during sync via `manage_relationship` with
`on_no_match: :ignore` — only weaknesses already present in the CWE catalog
are linked.

### `CveManagement.CAPEC.CapecMetadata`

Singleton resource (primary key `"singleton"`) storing the `Last-Modified`
header value and `last_synced_at` timestamp from the most recent successful
sync. Identical structure to `CWE.CweMetadata`.

### XML Parsing

Uses Erlang's built-in `:xmerl_scan` — no new dependencies. The parser
(`CapecXmlParser`) is structurally identical to `CweXmlParser`, differing
only in element names (`Attack_Pattern_Catalog`, `Attack_Patterns`,
`Attack_Pattern`) and field-specific parsing logic.

## Consequences

- No new Mix dependencies.
- A new `capec_sync` Oban queue (concurrency 1) is required in config.
- `CveManagement.CAPEC` must be added to the `ash_domains` list.
- Sync is idempotent (upsert on `capec_id`); re-running is safe.
- The `@reboot` schedule ensures the catalog is populated on first deploy
  without manual intervention.
- **CWE must be synced before CAPEC**: the sync action enforces this by
  asserting the `CweMetadata` singleton is present. Run `sync_cwe_catalog`
  first.
- CAPEC–CWE weakness links are best-effort: only CWE IDs already present in
  the local catalog are linked. Any CAPEC entry referencing a CWE not yet
  synced will have that weakness omitted from the join table until the next
  sync cycle.
