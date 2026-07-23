<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: find-cwe
description: Find the right CWE ID for a vulnerability. Use when filing a CVE and the CWE is unknown or needs verification.
---

# CWE Finder

Find the most appropriate CWE for the vulnerability using the Varsel MCP's local CWE catalog, then propose it onto the case.

## Search

Full-text search over name, description, mitigations, and consequences, best match first:

```
mcp__varsel__search_weaknesses(input: {query: "path traversal"})
```

Terms are ANDed by default, so a long descriptive query can match nothing. For broad recall, separate alternative terms with `OR` (e.g. `length OR quantity OR mismatch OR validation`) or wrap an exact phrase in double quotes. Start specific; widen with `OR` if you get too few hits.

Look for the most specific CWE that describes the **root cause**, not just the impact. Prefer **Base** level over **Class** (too broad) or **Variant** (too specific) when in doubt.

## Verify a known ID

If a CWE ID is already suggested (by the advisory or the user), confirm it fits:

```
mcp__varsel__get_weakness(input: {cwe_id: <ID>})
```

Check the name, description, and consequences against the vulnerability. If it does not fit, search for a better one.

## Output

Report the chosen CWE (id + name) and why it fits. Then, in the `/new-cve` flow, land it on the case (payload is the **id only** — no name):

```
create_case_proposal(input: {
  case_id: <id>, target: "weakness", operation: "insert",
  proposed_value: {"value": {"cwe_id": <ID>}},
  reasoning: "why this CWE matches the root cause"
})
```

Usually one CWE. Multiple are acceptable only when the vulnerability genuinely has distinct root causes — the exception, not the rule.