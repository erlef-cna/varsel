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

If you already picked a CWE (via `/find-cwe`), start there — MITRE maps each CWE to the attack patterns that exploit it, and Varsel exposes that link as its own tool:

```
mcp__varsel__get_weakness_related_attack_patterns(cwe_id: <ID>)
# → { ..., "related_attack_patterns": [{"capec_id": 126, "name": "Path Traversal", "description": "..."}, ...] }
```

Each pattern arrives identified by id, name and description. Pick the one(s) matching *how* this specific vulnerability is exploited, then read the full record with `get_attack_pattern`. This keeps the CWE and CAPEC consistent by construction. If the list is empty or none fit, fall back to search below.

## Search (fallback)

Full-text search over name, description, prerequisites, mitigations, and consequences, best match first:

```
mcp__varsel__search_attack_patterns(input: {query: "path traversal"})
```

The query never errors, whatever you type. Four things it recognizes:

- **Bare words are ANDed**, so a long descriptive query (e.g. "malformed input crash denial of service") often matches nothing.
- **`OR`** (either case) makes an alternation: `malformed OR crash OR length OR validation`. This is how you widen.
- **`"quoted words"`** requires them *adjacent*, which narrows: `"form hijacking"` skips a record that merely mentions both words apart.
- **`-word`** excludes: `spoofing -phishing`.

Words are stemmed, so `hijacking` also matches "hijack". Start with a specific 1–2 word phrase; if you get too few hits, re-run with `OR` between the candidate terms, then tighten with a quoted phrase or a `-` exclusion.

Results are ranked, and the tool returns the first 25 unless you pass a `limit`. Since the best match is first, take the top few rather than paging: a `limit` of 5 or less is usually the right ask.

Pick the most specific pattern that describes *how* the attack works, not just the outcome. Multiple CAPECs are fine when the vulnerability can be exploited via genuinely distinct techniques (e.g. both relative and absolute path traversal).

## Verify a known ID

```
mcp__varsel__get_attack_pattern(capec_id: <ID>)
```

Check the name and description against the actual attack technique. To confirm the pattern exploits the weakness you identified, ask for its links separately — `get_attack_pattern_relations(capec_id: <ID>)` returns a `weaknesses` array whose `cwe_id`s should include the case's CWE.

## Output

Report the chosen CAPEC(s) (id + name) and why each fits. Then, in the `/new-cve` flow, land each on the case as its own proposal (payload is the **id only** — no name):

```
mcp__varsel__propose_impact(input: {
  case_id: <id>, capec_id: <ID>,
  reasoning: "why this attack pattern matches"
})
```