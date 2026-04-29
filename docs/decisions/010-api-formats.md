<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
-->

# ADR-010: Ash GraphQL for the API + dedicated REST controllers for CVE/OSV JSON

**Status**: Accepted

## Context

The application needs two kinds of external API access:

1. **Case management API** — authenticated access for programmatic integrations
   with the case workflow (creating reports, querying cases, etc.)
1. **Public CVE/OSV data** — consumers of vulnerability data expect standard
   machine-readable formats: CVE JSON 5.x (MITRE standard) and OSV JSON (OpenSSF
   standard). These are widely consumed by tooling that expects a predictable REST
   interface, not GraphQL.

## Decision

- Use **Ash GraphQL** for the case management API and all authenticated operations.
  GraphQL introspection makes the schema self-documenting and flexible for clients.
- Add dedicated **Phoenix REST controllers** (`CveController`, `OsvController`)
  for the public CVE and OSV endpoints. These serve the exact standard JSON
  formats that consumers expect, without requiring GraphQL knowledge.

REST endpoints:

- `GET /cves/index.json` — CVE JSON 5.x index (see ADR-015 for details)
- `GET /cves/:cve_id.json` — CVE JSON 5.x detail (see ADR-015 for details)
- `GET /api/osv` — OSV JSON index
- `GET /api/osv/:cve_id` — OSV JSON detail

## Consequences

- Consumers of CVE/OSV data get a familiar REST interface with standard formats
- Case management consumers get a flexible GraphQL API
- Two API paradigms to maintain; keep the REST controllers thin (delegate to Ash
  queries)
- CVE JSON 5.x and OSV JSON schemas are stable standards; validate output against
  them in tests
