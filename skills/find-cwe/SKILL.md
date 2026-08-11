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

The query never errors, whatever you type. Four things it recognizes:

- **Bare words are ANDed**, so a long descriptive query often matches nothing.
- **`OR`** (either case) makes an alternation: `length OR quantity OR mismatch`. This is how you widen.
- **`"quoted words"`** requires them *adjacent*, which narrows: `"path traversal"` skips a record that merely says "a traversal of the path".
- **`-word`** excludes: `traversal -relative`.

Words are stemmed, so `traversal` also matches "traversals". Start specific, widen with `OR`, then tighten with a quoted phrase or a `-` exclusion.

Results are ranked, and the tool returns the first 25 unless you pass a `limit`. Since the best match is first, take the top few rather than paging: a `limit` of 5 or less is usually the right ask.

Look for the most specific CWE that describes the **root cause**, not just the impact. Prefer **Base** level over **Class** (too broad) or **Variant** (too specific) when in doubt.

## Verify a known ID

If a CWE ID is already suggested (by the advisory or the user), confirm it fits:

```
mcp__varsel__get_weakness(cwe_id: <ID>)
```

Check the name, description, and consequences against the vulnerability. If it does not fit, search for a better one, or walk the hierarchy with `get_weakness_related_weaknesses(cwe_id: <ID>)` to find the parent or child that fits better.

## Output

Report the chosen CWE (id + name) and why it fits. Then, in the `/new-cve` flow, land it on the case (payload is the **id only** — no name):

```
mcp__varsel__propose_weakness(input: {
  case_id: <id>, cwe_id: <ID>,
  reasoning: "why this CWE matches the root cause"
})
```

Usually one CWE. Multiple are acceptable only when the vulnerability genuinely has distinct root causes — the exception, not the rule.