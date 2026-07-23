<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: find-capec
description: Find the right CAPEC attack pattern for a vulnerability. Use when filing a CVE and the CAPEC is unknown or needs verification.
---

# CAPEC Finder

Find the most appropriate CAPEC attack pattern(s) using the Varsel MCP's local CAPEC catalog, then propose them onto the case.

## Start from the CWE (preferred)

If you already picked a CWE (via `/find-cwe`), start there — MITRE maps each CWE to the attack patterns that exploit it, and Varsel exposes that link directly. `get_weakness` returns a `related_attack_patterns` array of full CAPEC entries:

```
mcp__varsel__get_weakness(input: {cwe_id: <ID>})
# → { ..., "related_attack_patterns": [{"capec_id": 126, "name": "Path Traversal", ...}, ...] }
```

Pick from `related_attack_patterns` the pattern(s) that match *how* this specific vulnerability is exploited. This keeps the CWE and CAPEC consistent by construction. If the list is empty or none fit, fall back to search below.

## Search (fallback)

Full-text search over name, description, prerequisites, mitigations, and consequences:

```
mcp__varsel__search_attack_patterns(input: {query: "path traversal"})
```

Pick the most specific pattern that describes *how* the attack works, not just the outcome. Multiple CAPECs are fine when the vulnerability can be exploited via genuinely distinct techniques (e.g. both relative and absolute path traversal).

## Verify a known ID

```
mcp__varsel__get_attack_pattern(input: {capec_id: <ID>})
```

Check the name and description against the actual attack technique. The returned record's `weaknesses[].cwe_id` should include the case's CWE — that confirms the pattern exploits the weakness you identified.

## Output

Report the chosen CAPEC(s) (id + name) and why each fits. Then, in the `/new-cve` flow, land each on the case as its own proposal:

```
create_case_proposal(input: {
  case_id: <id>, target: "impact", operation: "insert",
  proposed_value: {"value": {"capec_id": <ID>, "name": "<Name>"}},
  reasoning: "why this attack pattern matches"
})
```