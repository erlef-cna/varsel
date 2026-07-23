<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: verify
description: Verify a Varsel case renders a correct CVE record. Use before requesting publish, to check conventions, schema, and lint.
---

# CVE Verifier

Reference: https://cna.erlef.org/cve-criteria

Verify the case specified by the user (or the current working case). Fix any issues **as proposals** (never by editing rendered JSON), then confirm everything passes.

## Step 1 — Render the preview

```
mcp__varsel__render_case_preview(input: {id: <case-id>})
```

`render_case_preview` derives on demand and returns the rendered CNA container, a validation result, applied overrides, and **publish blockers**. Any publish blocker is an automatic FAIL — resolve it before anything else. Use the rendered container as the record under test for the checks below.

Note: the preview reflects **accepted** proposals only. If you (or the user) just submitted fixes as new proposals, they must be accepted before they show up here — re-render after acceptance.

## Step 2 — Validators

Run the MCP validators on the rendered CNA JSON:

```
mcp__varsel__validate_cve_record(input: {cve_json: <rendered container>})
```

This runs schema + cvelint + hex-package checks together. If you need to isolate a failure, the individual tools are `validate_cve_record_schema`, `validate_cve_record_cvelint`, and `validate_cve_record_hex_packages`. Fix any error (as a proposal, then re-render) before proceeding.

## Step 3 — Convention checklist

Read the rendered record and verify each item. Report PASS/FAIL for each.

### Metadata
- [ ] `cveMetadata` contains `assignerOrgId`, `assignerShortName`, `cveId`, `state`. Date fields, if present, are set externally — leave them.
- [ ] `cveMetadata.state` is `"PUBLISHED"`.

### programRoutines and modules
- [ ] All `programRoutines` use Erlang notation `module:function/arity` — Elixir modules use the `'Elixir.ModuleName'` atom prefix (e.g. `'Elixir.Decimal':add/2`), not dot notation.
- [ ] `programRoutines` list vulnerable routines only — no bookkeeping helpers the fix commit happens to touch.
- [ ] Cross-language reachability: when vulnerable code is behind a language boundary (Rust NIF, C BIF, port driver), every affected entry lists **both sides** of the call chain — the implementing function *and* the Erlang/Elixir wrapper callers invoke — and `modules` lists the analogous module names on both sides.

### Descriptions
- [ ] Plain-text description (`value`) present.
- [ ] HTML description (`supportingMedia`, `type: "text/html"`) present.
- [ ] HTML uses `<tt>` for code/paths and `<p>` for paragraphs.
- [ ] Description does not mention other CVE IDs — the vulnerability class is named instead.
- [ ] The "This issue affects …" sentence ends with a real version, not a bare `TODO` (use `before TODO` if the fix version is genuinely unknown).

### Configurations
- [ ] If present, each entry has both plain text (`value`) and HTML.

### Affected entries (mostly derived — check they came out right)
- [ ] No version entry uses `versionType: "purl"`.
- [ ] Git `changes` entries use the fix **commit SHA**, not a release-tag SHA.
- [ ] `defaultStatus` is `"unaffected"` on every entry whose versions bound a range. `"affected"` implicitly marks unlisted versions as vulnerable and is almost always wrong.
- [ ] `repo` URL has no `.git` suffix on GitHub entries and is consistent across all entries for the same project.
- [ ] The `pkg:github/...` (source-repo) entry contains only `versionType: "git"` blocks — no duplicate semver block (that belongs on the package-registry entry).
- [ ] `cpes` present on each affected entry.
- [ ] `cpeApplicability` present at the top level, mirroring the version ranges.
- [ ] `cpeApplicability` operator orientation: outer node `"OR"`, each inner `cpeMatch` group `"AND"`. Do not invert.

Detect the type from the first affected entry's `packageURL` and apply the matching rules:

**OTP** (`pkg:otp/<lib>`):
- [ ] Exactly two affected entries.
- [ ] First: `pkg:otp/<lib>`, `versionType: "otp"`. Second: `pkg:github/erlang/otp`, `otp` blocks then `git` blocks.
- [ ] First entry `programFiles` are library-root-relative (`src/ssh_sftpd.erl`); second entry `programFiles` are full repo path (`lib/ssh/src/ssh_sftpd.erl`).
- [ ] Each entry has `programFiles`, `programRoutines`, `modules`.

**Gleam compiler** (`pkg:sid/gleam.run/gleam`):
- [ ] First: `pkg:sid/gleam.run/gleam`, `versionType: "semver"`. Second: `pkg:github/gleam-lang/gleam`, both `semver` and `git` blocks. Optional third: `pkg:oci/gleam?repository_url=ghcr.io/gleam-lang` with per-image `versionType: "other"` entries.
- [ ] Each entry has `programFiles`, `programRoutines`, `modules`.

**Hex package** (`pkg:hex/<name>`):
- [ ] Two entries (`pkg:hex/<name>` + `pkg:github/<owner>/<repo>`), plus an optional `pkg:npm/<name>` entry only when the library ships a JS client on npm and the vulnerable file is in the npm tarball.
- [ ] First: `pkg:hex/<name>`, `semver`. Last github entry: `git`. If an npm entry exists, its `programFiles` reflect the real npm-tarball paths and its range matches what shipped to npm.
- [ ] Each entry has `programFiles`, `programRoutines`, `modules`.

### Cross-check against the advisory

Find the GHSA URL in references (first `vendor-advisory`), re-fetch it:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

- [ ] **Stale TODOs.** Every `TODO` in the record is still a `TODO` in the advisory's `patched_versions`. If the advisory now has a real fix version, propose the fix commit and re-derive.
- [ ] **Version ranges match.** Each derived affected range matches the advisory's `vulnerable_version_range`. A mismatch means a wrong boundary SHA on the case — investigate before trusting either side.
- [ ] **Credits coverage.** Every advisory credit appears with the right role (reporter → finder, remediation_developer → remediation developer, coordinator → analyst, …). Do not skip `pending` credits.

### Source
- [ ] `source.discovery` is `"EXTERNAL"`, `"INTERNAL"`, or `"UNKNOWN"`.

### Credits
- [ ] Reporters → `finder`; fix authors → `remediation developer`; reviewers → `remediation reviewer`; analysts → `analyst`.

### Workarounds
- [ ] No entry says "apply patch"/"apply the patch".
- [ ] No entry says "There are no workarounds".
- [ ] If none genuine: `workarounds` omitted entirely.

### References (in order)
- [ ] First: vendor advisory `["vendor-advisory"]` (GHSA → `["vendor-advisory", "related"]`).
- [ ] Second: `https://cna.erlef.org/cves/CVE-<num>.html` `["related"]` (add `"third-party-advisory"` if no vendor advisory).
- [ ] Third: `https://osv.dev/vulnerability/EEF-CVE-<num>` `["related"]`.
- [ ] OTP: `https://www.erlang.org/doc/system/versions.html#order-of-versions` `["x_version-scheme"]` present.
- [ ] At least one `"patch"`-tagged reference (use a `/TODO` URL if the patch commit is unknown; a fully-unpatched CVE with no patch reference must be confirmed with the user first).

### CVSS
- [ ] `baseScore` is not `0.0` — i.e. `cvss_v4` is set on the case and derived through.

## Output

List each failed check with the specific problem and the proposal that fixes it (or that is needed). If everything passes and there are no publish blockers, confirm "All checks passed."