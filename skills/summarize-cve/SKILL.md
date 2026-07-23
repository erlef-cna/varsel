<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: summarize-cve
description: Produce a concise technical markdown summary of a CVE. Use when preparing a human-readable write-up from a Varsel case or published CVE record.
---

# CVE Summarizer

Produce a concise technical markdown summary of a CVE. The output is for a security-oriented audience, not an end-user advisory.

## Step 1 — Load the record

Pull the data from the Varsel MCP:

- **Published CVE:** `mcp__varsel__get_cve(input: {cve_id: "CVE-..."})`.
- **Working case:** `mcp__varsel__get_case(input: {...})`, and `mcp__varsel__render_case_preview(input: {id: <case-id>})` for the rendered container (affected ranges, references, etc.).

Extract:
- Title and CVE ID
- Description (plain-text value)
- Affected package, version range, program files, program routines
- CVSS score and vector
- References (look for a GHSA link in the vendor-advisory reference)
- Credits
- Configurations / workarounds if present
- Patch commit URL(s) from references tagged `"patch"`
- Introducing commit SHA from the git version entry (`version` field, `versionType: "git"`)

## Step 2 — Fetch the GHSA (if present)

If the references contain a GitHub Security Advisory URL (`github.com/<owner>/<repo>/security/advisories/GHSA-...`), fetch it:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

Use the GHSA `description` for additional technical detail (often richer than the CVE description). Supplemental context only, not authoritative.

## Step 3 — Produce the markdown summary

Write the output to `/tmp/cve-summary-<CVE-ID>.md`. Output exactly the sections below. All section headings must be H3 (`###`). Keep each section concise. No code blocks or source-code snippets anywhere — describe code in prose, referencing file and function names. Use `TODO` for any unknown value, both in URLs and prose (e.g. `from 0.1.0 before TODO`); do not paraphrase as "latest release at time of filing".

---

### Summary

One short paragraph: what the vulnerability is, what it allows, and who can trigger it. No bullet points.

### Details

Technical deep-dive, structured with bold sub-headings if it is a multi-step chain (e.g. **1. Input handling**, **2. Unsafe processing**, **3. Execution**). Include relevant file and function names. No code blocks. Omit filler.

### PoC

Numbered steps: the minimum to reproduce. Not a complete exploit — just the attack path. Skip setup boilerplate unless non-obvious.

### Impact

One or two sentences on the user-visible consequences (what an attacker can do, who is affected in practical terms). Do not include affected version ranges, the CVSS score/severity, or CVSS metric reasoning, and never write "no fix available" — CVEs are only published once a fix exists.

### References

A flat list, in this order:
1. Introducing commit (from the git version entry — `TODO` if absent)
2. Patch commit(s) (from `"patch"`-tagged references — `TODO` if unknown)
3. Any other genuinely useful context (upstream bug reports, write-ups, docs)

Never include the CNA advisory page (`cna.erlef.org/cves/...`), the CVE.org record, the GHSA link, or the OSV link — those are aggregators pointing back at this same data.

Format each line:
```
* Label: <URL>
```

---

## Notes

- No CVSS vector strings in the output — the Impact prose is enough.
- No "Credits" section unless the user asks.
- No "Workarounds"/"Configurations" section unless the CVE has non-trivial ones.
- No dates needed.
- Keep it tight: a few paragraphs, not a wall of text.