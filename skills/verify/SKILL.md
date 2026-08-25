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

## Step 1 — Refresh and get the preview

```
mcp__varsel__refresh_case_derivation(id: <case-id>)
```

Refresh first: the preview renders from the *cached* derivation and does not recompute it, so a stale cache renders stale (often empty) version ranges. `refresh_case_derivation` recomputes **and** returns the freshly rendered preview, so you get the record to check from this one call — no separate `render_case_preview` needed (that tool exists too, but it would render the same cache without recomputing).

Pass `refresh: true` when the package repository may have changed since the last derivation, most often when a fix shows as unreleased and you are checking whether its tag has landed. It refetches the repository state before deriving; without it, derivation can reuse recently cached git state and miss tags pushed in the meantime.

The returned `preview` holds the full CVE record (`preview.cve_record`, using a `CVE-0000-0000` placeholder until an ID is assigned) and **publish blockers** (`preview.blockers`). Any publish blocker is an automatic FAIL — resolve it before anything else. Use the CNA container at `preview.cve_record.containers.cna` as the record under test for the convention checklist.

`preview.osv_record` is the OSV document the record would publish as, enumerated hex.pm `versions` included (`preview.osv_status` says why when there is none).

Note: the preview reflects **accepted** proposals only. If you (or the user) just submitted fixes as new proposals, they must be accepted before they show up here — accept, refresh, then re-render.

## Step 2 — Validators

```
mcp__varsel__validate_case(filter: {field: "id", operator: "eq", value: "<case-id>"})
```

This is a read, addressed by filter rather than by an `id` argument. It returns the `validation` result — the schema + cvelint + hex-package check (`{valid, errors}`) over the rendered record — and nothing else of the case. Any error is a FAIL. Fix it as a proposal, then re-run.

Reach for the standalone `validate_cve_record` (and the per-check `validate_cve_record_schema` / `_cvelint` / `_hex_packages`) only to isolate a specific failure against a hand-modified record.

## Step 3 — Convention checklist

Read the rendered record and verify each item. Report PASS/FAIL for each.

### People
- [ ] `mcp__varsel__get_case(id: <case-id>)` shows, across `assignments` and `invites`, the advisory's collaborators and credited users, the repository owner (when a user, not an organization), and the owners of each affected hex package. Add anyone missing with `mcp__varsel__grant_case_access`; never remove anyone.

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
- [ ] First: `pkg:otp/<lib>?repository_url=…&vcs_url=…` (both qualifiers naming the erlang/otp repository), `versionType: "otp"`. Second: `pkg:github/erlang/otp`, `otp` blocks then `git` blocks.
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
- [ ] **Version ranges match.** Each derived affected range matches the advisory's `vulnerable_version_range`. A mismatch means a wrong boundary SHA on the case — investigate before trusting either side. An OTP package fixed on several maintenance lines states one span open from the introducing release with a fix per line, rather than one range per line; check each fix against the advisory, not the span.
- [ ] **Credits coverage.** Every advisory credit appears, carrying every role that applies: a GHSA holds one role per person, the CVE record may hold several. Do not skip `pending` credits.

### Source
- [ ] `source.discovery` is `"EXTERNAL"`, `"INTERNAL"`, or `"UNKNOWN"`.

### Credits
- [ ] Each credit's roles match what the person did, per the CVE schema definitions (finder identified, reporter reported, analyst validated, coordinator facilitated the response, remediation developer/reviewer/verifier on the fix). Analyst and coordinator are distinct; a person carries every role that applies, not only the single one a GHSA could express.

### Workarounds
- [ ] No entry says "apply patch"/"apply the patch".
- [ ] No entry says "There are no workarounds".
- [ ] If none genuine: `workarounds` omitted entirely.

### References (in order)
- [ ] First: vendor advisory `["vendor-advisory"]` (GHSA → `["vendor-advisory", "related"]`).
- [ ] Second: `https://cna.erlef.org/cves/CVE-<num>.html` `["related"]` (add `"third-party-advisory"` if no vendor advisory).
- [ ] Third: `https://osv.dev/vulnerability/EEF-CVE-<num>` `["related"]`.
- [ ] OTP: `https://www.erlang.org/doc/system/versions.html#order-of-versions` `["x_version-scheme"]` present — derived from any OTP-versioned entry, so its absence means no entry is OTP-versioned.
- [ ] At least one `"patch"`-tagged reference, unless the vulnerability is unpatched.

### CVSS
- [ ] `baseScore` is not `0.0` — i.e. `cvss_v4` is set on the case and derived through.

## Output

List each failed check with the specific problem and the proposal that fixes it (or that is needed). If everything passes and there are no publish blockers, confirm "All checks passed."