<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-012: Case and CVE Record Data Model

**Status**: Proposed (not yet implemented — current implementation uses
`cve_json` as an opaque blob)

## Context

The `Case` and `CveRecord` resources must capture all data needed to produce
valid **CVE JSON 5.x** and **OSV JSON** records, support structured human and
AI review of every field, and track the reasoning behind each value.

The actual CVE/OSV records published by EEF (CVE-2025-4748, CVE-2025-4754,
CVE-2025-48038) reveal the full breadth of fields used in practice. The current
spec (`CveRecord`) stores `cve_json` and `osv_json` as opaque blobs, which
prevents structured editing, AI-assisted field-by-field proposals, and
granular discussion threads.

The data model must support:

1. All CVE JSON 5.x `cna` container fields actually used by EEF
1. All OSV JSON fields
1. Structured proposals and discussions on individual fields — by humans and AI
1. Reasoning / justification captured alongside every proposed value
1. Acceptance / rejection of proposals with audit trail

## Decision

### 1. Replace opaque JSON blobs with structured fields on `CveRecord`

`cve_json` and `osv_json` remain as computed/derived outputs (generated on
publish), but all *editable* data lives in typed, named fields that map
directly to the CVE and OSV schemas. This enables:

- Field-level encryption (Ash Cloak) on sensitive fields
- Field-level proposals and discussion (see §2)
- AI skill targeting specific fields (see §3)
- Schema validation before publish

All free-text fields (description, workarounds, configurations) are stored as
**Markdown**. At publish time the system derives:

- A plain-text version (Markdown stripped to text) — used as CVE JSON
  `descriptions[].value` and the body of OSV `details`
- An HTML version (Markdown rendered to HTML) — used as CVE JSON
  `descriptions[].supportingMedia[type=text/html].value`

This avoids storing redundant representations and keeps the editable source of
truth human-readable.

#### `CveRecord` — structured fields

### Identity / metadata

| Field | Type | Encrypted? | CVE JSON path | OSV path |
| --- | --- | --- | --- | --- |
| `cve_id` | string | No | `cveMetadata.cveId` | `aliases[]` |
| `title` | string | Yes | `containers.cna.title` | `summary` |
| `description` | text (Markdown) | Yes | `containers.cna.descriptions[].value` / `supportingMedia[html]` | `details` (intro section) |
| `workarounds` | text (Markdown, nullable) | Yes | `containers.cna.workarounds[].value` / `supportingMedia[html]` | `details` (workaround section) |
| `configurations` | text (Markdown, nullable) | Yes | `containers.cna.configurations[].value` / `supportingMedia[html]` | — |
| `source_discovery` | enum: `user`, `internal`, `unknown`, `external` | No | `containers.cna.source.discovery` | — |

### CVSS 4.0

| Field | Type | Encrypted? | CVE JSON path | OSV path |
| --- | --- | --- | --- | --- |
| `cvss_vector` | string (nullable) | No | `containers.cna.metrics[].cvssV4_0.vectorString` | `severity[type=CVSS_V4].score` |
| `cvss_score` | decimal (nullable) | No | `containers.cna.metrics[].cvssV4_0.baseScore` | — |
| `cvss_severity` | string (nullable) | No | `containers.cna.metrics[].cvssV4_0.baseSeverity` | — |

Score and severity are derived from the vector at publish time using a CVSS
library. Storing them separately allows display without re-parsing.

### Weakness / attack classifications

| Field | Type | Encrypted? | CVE JSON path | OSV path |
| --- | --- | --- | --- | --- |
| `cwe_ids` | `{id, description}[]` (jsonb) | No | `containers.cna.problemTypes[].descriptions[]` | `database_specific.cwe_ids[]` |
| `capec_ids` | `{id, description}[]` (jsonb) | No | `containers.cna.impacts[].capecId` + `.descriptions[]` | `database_specific.capec_ids[]` |

The full `{id, description}` pair is stored so the publish step does not need
to re-derive human-readable labels.

### Affected products

Stored as a jsonb array `affected` mirroring `containers.cna.affected[]`. Each
element follows this shape:

```json
{
  "vendor": "Erlang",
  "product": "OTP",
  "package_name": "erlang/otp",
  "package_url": "pkg:github/erlang/otp",
  "collection_url": "https://github.com",
  "repo": "https://github.com/erlang/otp",
  "modules": ["stdlib"],
  "program_files": ["lib/stdlib/src/zip.erl"],
  "program_routines": [{"name": "zip:unzip/1"}],
  "cpes": ["cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"],
  "default_status": "unknown",
  "versions": [
    {
      "version": "17.0",
      "status": "affected",
      "less_than": "*",
      "version_type": "otp",
      "changes": [
        {"at": "28.0.1", "status": "unaffected"}
      ]
    }
  ]
}
```

OSV `affected[].ranges` are derived from this data at publish time.

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `affected` | jsonb array | Yes | Array of product entries above |
| `cpe_applicability` | jsonb (nullable) | No | `containers.cna.cpeApplicability` — often derived from `affected`; rarely edited manually |

### References

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `references` | `{url, tags[]}[]` (jsonb) | No | `containers.cna.references[]`; CVE JSON 5.x tag vocabulary: `patch`, `vendor-advisory`, `related`, `x_version-scheme`, etc. OSV `references[].type` is derived from tags at publish time (see §5). |

### Credits

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `credits` | `{name, type, lang}[]` (jsonb) | Yes | `containers.cna.credits[]`; encrypted until publish because it may identify the reporter before disclosure |

### OSV-specific fields

| Field | Type | Encrypted? | OSV path | Notes |
| --- | --- | --- | --- | --- |
| `osv_id` | string (nullable) | No | `id` | e.g., `EEF-CVE-2025-4748`; set on publish |
| `osv_aliases` | string[] (nullable) | No | `aliases[]` | GHSA IDs and the CVE ID; populated from known sources |
| `osv_related` | string[] (nullable) | No | `related[]` | Adjacent OSV IDs |

### Publication timestamps (managed by system, not directly editable)

| Field | Type | Notes |
| --- | --- | --- |
| `published_at` | utc_datetime (nullable) | Set when published to MITRE |
| `inserted_at` | utc_datetime | |
| `updated_at` | utc_datetime | |

**Fields removed from the previous `CveRecord` spec** (superseded by the above):

- `cve_json`, `osv_json` — replaced by computed output generated on publish
- `cvss_vector`, `cvss_score`, `cvss_base_severity` — renamed to drop the
  version suffix (CVSS 4.0 only); `cvss_base_severity` → `cvss_severity`
- `patch_url`, `introduced_commit`, `fixed_commit` — subsumed by `affected`
  (git version ranges) and `references` (patch URLs)

**Fields removed from `Case`** (superseded):

- `description` — the Case retains only `title` (internal working title, not
  the published CVE title); the CVE description lives on `CveRecord`

______________________________________________________________________

### 2. `CveFieldProposal` — structured proposals and discussions

Every field on `CveRecord` can be the subject of one or more proposals. A
proposal carries the proposed value, the reasoning behind it, and its acceptance
state.

#### Resource: `CveFieldProposal`

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `id` | UUID | No | |
| `cve_record_id` | UUID (FK) | No | |
| `case_id` | UUID (FK) | No | Denormalized for policy checks |
| `field_name` | string | No | Name of the `CveRecord` field, e.g. `cvss_vector`, `affected` |
| `proposed_value` | jsonb | Yes | The proposed value (jsonb accommodates all field types) |
| `reasoning` | text (Markdown) | Yes | Justification for the proposed value |
| `actor_type` | enum: `human`, `ai` | No | |
| `actor_user_id` | UUID (FK, nullable) | No | Set when `actor_type = human` |
| `ai_skill_run_id` | UUID (FK, nullable) | No | Set when `actor_type = ai`; links to `AiSkillRun` |
| `status` | enum: `open`, `accepted`, `rejected`, `superseded` | No | |
| `resolved_by_id` | UUID (FK, nullable) | No | User who accepted or rejected |
| `resolved_at` | utc_datetime (nullable) | No | |
| `resolution_note` | text (Markdown, nullable) | Yes | Optional note explaining acceptance/rejection |
| `parent_proposal_id` | UUID (FK, nullable) | No | Links a counter-proposal to the proposal it supersedes |
| `inserted_at` | utc_datetime | No | |

**Lifecycle:**

1. Any actor (human or AI) creates an `open` proposal for a field.
1. A PoC or assigned Supporter `accept`s a proposal → the value is written to
   `CveRecord`; all other `open` proposals for the same field are marked
   `superseded`.
1. Any actor can `reject` a proposal with an optional note.
1. A new proposal for the same field while another is open creates a sibling.
   Setting `parent_proposal_id` marks it explicitly as a counter-proposal.

**Ash Policies:**

- `poc`: full CRUD on proposals for any case
- `supporter`: can create and reject proposals on assigned cases; can accept
  proposals on assigned cases
- AI actor (system, no user session): can only create proposals; cannot accept
  or reject

______________________________________________________________________

### 3. `CveFieldComment` — threaded comments on proposals

Allows humans and AI to comment on a specific proposal before it is resolved.

#### Resource: `CveFieldComment`

| Field | Type | Encrypted? | Notes |
| --- | --- | --- | --- |
| `id` | UUID | No | |
| `proposal_id` | UUID (FK) | No | |
| `case_id` | UUID (FK) | No | Denormalized for policy checks |
| `body` | text (Markdown) | Yes | |
| `actor_type` | enum: `human`, `ai` | No | |
| `actor_user_id` | UUID (FK, nullable) | No | |
| `ai_skill_run_id` | UUID (FK, nullable) | No | |
| `inserted_at` | utc_datetime | No | |

Comments are append-only (no update/delete). Ash Events covers all mutations
for the audit trail.

______________________________________________________________________

### 4. AI skill → field mapping

Each AI skill that targets CVE fields creates `CveFieldProposal` records with
`actor_type: :ai` and `ai_skill_run_id` set. The `AiSkillRun.output` includes
the list of proposal IDs created so the UI can link from skill run to proposals.

| Skill | Fields proposed |
| --- | --- |
| `triage` | No proposals; produces boolean + reasoning stored in `AiSkillRun.output` only |
| `cvss_assist` | `cvss_vector` |
| `cwe_capec` | `cwe_ids`, `capec_ids` |
| `description_writer` | `description`, `workarounds`, `configurations` |
| `introducing_commit` | `affected` (adds/updates a git version range for the introducing commit) |
| `patch_locator` | `references` (adds patch URLs), `affected` (adds fix commits/versions) |
| `prioritization` | No proposals; urgency score stored in `AiSkillRun.output` only |

Users must explicitly accept every proposal. AI never directly mutates
`CveRecord`.

______________________________________________________________________

### 5. Publish-time derivation

When the `publish` action runs on `CveRecord`, the system:

1. Derives plain-text and HTML from each Markdown text field:
   - `description` → `cna.descriptions[].value` (plain text) +
     `cna.descriptions[].supportingMedia[type=text/html].value` (HTML)
   - `workarounds` → `cna.workarounds[].value` + `supportingMedia`
   - `configurations` → `cna.configurations[].value` + `supportingMedia`
1. Derives `cvss_score` and `cvss_severity` from `cvss_vector` if not already set
1. Assembles `cve_json` (CVE JSON 5.x) from all structured fields
1. Assembles `osv_json` (OSV JSON 1.x) using the mapping in §6
1. Validates both against their respective JSON schemas
1. Submits `cve_json` to MITRE CVE Services API
1. Sets `osv_id` and `published_at`
1. Stores the final `cve_json` and `osv_json` blobs on `CveRecord` for audit
   and re-serving (these are outputs, not the editable source of truth)

______________________________________________________________________

### 6. Field mapping reference

#### CVE JSON 5.x → `CveRecord`

```text
cveMetadata.cveId                                   → cve_id
cveMetadata.datePublished                           → published_at
containers.cna.title                                → title
containers.cna.descriptions[lang=en].value          → description (plain-text render)
containers.cna.descriptions[lang=en]
  .supportingMedia[type=text/html].value            → description (HTML render)
containers.cna.workarounds[lang=en].value           → workarounds (plain-text render)
containers.cna.workarounds[lang=en]
  .supportingMedia[type=text/html].value            → workarounds (HTML render)
containers.cna.configurations[lang=en].value        → configurations (plain-text render)
containers.cna.configurations[lang=en]
  .supportingMedia[type=text/html].value            → configurations (HTML render)
containers.cna.source.discovery                     → source_discovery
containers.cna.metrics[].cvssV4_0.vectorString      → cvss_vector
containers.cna.metrics[].cvssV4_0.baseScore         → cvss_score
containers.cna.metrics[].cvssV4_0.baseSeverity      → cvss_severity
containers.cna.problemTypes[].descriptions[]        → cwe_ids
containers.cna.impacts[]                            → capec_ids
containers.cna.affected[]                           → affected
containers.cna.cpeApplicability                     → cpe_applicability
containers.cna.references[]                         → references
containers.cna.credits[]                            → credits
```

#### OSV JSON → `CveRecord`

```text
id                                                  → osv_id
summary                                             → title
details                                             → description + workarounds (Markdown sections)
aliases[]                                           → osv_aliases (includes cve_id)
related[]                                           → osv_related
severity[type=CVSS_V4].score                        → cvss_vector
affected[].ranges[type=GIT]                         → derived from affected[].versions (git versionType)
affected[].ranges[type=SEMVER/ECOSYSTEM]            → derived from affected[].versions (semver/ecosystem)
database_specific.cwe_ids[]                         → cwe_ids[].id
database_specific.capec_ids[]                       → capec_ids[].id
references[].type + .url                            → references[] (type mapped back to CVE tags)
credits[].name, .type                               → credits[].name, .type (type lowercased)
```

#### OSV reference type ↔ CVE JSON tag mapping

| CVE JSON tag | OSV reference type |
| --- | --- |
| `patch` | `FIX` |
| `vendor-advisory` | `ADVISORY` |
| `related` | `WEB` |
| `x_version-scheme` | `WEB` |
| *(none / other)* | `WEB` |

## Consequences

- All CVE and OSV fields are individually addressable, editable, and
  validatable before publish
- Storing Markdown as the canonical text format gives a single source of truth;
  plain-text and HTML are always derived consistently
- CVSS 4.0 only; no v3 fields in the schema (the publish step emits a single
  `cvssV4_0` metrics entry)
- `CveFieldProposal` and `CveFieldComment` are first-class resources with full
  Ash Events audit trail
- AI skills create proposals that humans must explicitly accept — the human is
  always in the loop
- `affected` and `cpe_applicability` remain jsonb (not normalized
  sub-resources) because their schemas vary by ecosystem; normalizing them
  would add migration complexity without meaningful query benefit for v1
- Two new resources (`CveFieldProposal`, `CveFieldComment`) join the `CVE`
  domain
- `spec.md` must be updated to reflect the new `CveRecord` field list and the
  two new resources
