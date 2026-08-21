<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: new-cve
description: File a new CVE as a Varsel case using the MCP. Use when starting a new CVE from a GHSA link or advisory URL and driving it through the case workflow to publish.
---

# New CVE Filing

You file CVEs through the **Varsel MCP** (`mcp__varsel__*` tools). This assumes the Varsel MCP server is already installed and authenticated (`/mcp`); see <https://cna.erlef.org/api-access#mcp>. If the `mcp__varsel__*` tools are unavailable, stop and have the user connect it first.

The unit of work is a **case**. You describe the vulnerability as **facts** — commit SHAs, package channels, references, credits, weaknesses, impacts — by submitting **field-level proposals**. Varsel **derives** the affected version ranges from the commit SHAs and **renders** the CNA record for you. You do not write version ranges, `cpeApplicability`, `programFiles` prefixes, or any CVE JSON by hand: state the facts, let the server compute the record.

Every change to a case is a **proposal**. There is one typed `mcp__varsel__propose_*` tool per thing you can change — pick the tool that names it (`propose_title`, `propose_cvss`, `propose_weakness`, `propose_reference`, `propose_credit`, `propose_affected_package` / `propose_otp_affected_package` / `propose_elixir_affected_package` / `propose_gleam_affected_package`, `propose_package_channel`, `propose_version_event`, `propose_delete`, …). Each takes `case_id`, `reasoning`, and the typed fields for that one change. Proposals are reviewed and accepted by a human — you author them, you never self-approve.

A human accepts or declines your proposals **in the UI, out of band** — this can happen at any time while you work, and you get no notification. So don't assume a proposal is still open just because you didn't accept it. To see the true state, use `mcp__varsel__list_case_proposals` (it returns proposals in **all** states — open, accepted, declined); `list_open_case_proposals` shows only the still-open ones, so an empty result there means "nothing left to accept," not "nothing was ever proposed." Listings carry the proposed value rather than the author's reasoning; read that on a single proposal with `mcp__varsel__get_case_proposal`.

Work through the steps interactively. Pause after each discussion step for the user before proceeding.

## Step 1 — Fetch advisory details

Given a GHSA URL or advisory link, fetch it via the GitHub API:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

Extract and present:
- Summary and description
- Affected package + version range
- Credits — for each GitHub login in `credits`, look up the real name via `gh api /users/<login>` (`name` field); never guess from the username. Known overrides:
  - `IngelaAndin` → `Ingela Anderton Andin`
  - `maennchen` → name `Jonatan Männchen`; when acting in his EEF capacity (e.g. analyst/coordinator) set `organization: "EEF"` — EEF goes in the `organization` field, never in `name` (Varsel renders `name / organization` itself)
  - `u3s` → `Jakub Witczak`
- CVSS if present (starting point only)
- Fix commit / patched version if available
- CVE ID if already assigned in the advisory

Check for prior art / duplicates: `mcp__varsel__list_cves_by_purl` (e.g. `pkg:hex/<name>`) and `mcp__varsel__list_cves` / `mcp__varsel__list_cases`. Keep things consistent with existing published CVEs.

Every list tool returns the first **25** rows unless you pass a `limit` (itself capped at 250), and says nothing when it truncates. A short result is not evidence you have seen everything, so filter for what you want rather than paging, and re-run with `result_type: "count"` when you need the real total.

**Do not treat the advisory as authoritative.** It may have been filed by someone unfamiliar with CVE conventions or the real scope. Flag anything suspicious.

## Step 2 — Open or locate the case

A case may already exist (an inbound vulnerability report accepted into a case, or a case the user points you at).

- **Existing:** find it with `mcp__varsel__list_cases`, filtering on the upstream repository — `{"affects_repo": {"input": {"repo_url": "https://github.com/<owner>/<repo>"}, "eq": true}}` — which matches the repositories of the case's affected packages. Read it with `mcp__varsel__get_case`, and read its proposals with `mcp__varsel__list_case_proposals` (all states, so you see what's already been accepted, not just what's still open).
- **New:** if none exists, open a fresh draft with `mcp__varsel__open_case(input: {title: "<advisory title>"})`. It returns the new case (state `draft`); use its `id` as the `case_id` for every proposal below. You can seed just the title here — all other content lands as proposals in the later steps.

The rest of this skill assumes you have a `case_id`.

Once you have it, put the people on the case with `mcp__varsel__grant_case_access(id: <case-id>, input: {strategy, username})`, one call per person: the advisory's collaborators and credited users (`strategy: "github"`), the repository owner when it is a user rather than an organization (`strategy: "github"`), and the owners of each affected hex package from `https://hex.pm/api/packages/<package>` (`strategy: "hex"`). The server assigns people who have an account and invites the rest; `get_case` lists both as `assignments` and `invites`, so only add who is missing. Never remove anyone.

## Step 3 — CVSS scoring

Use the `/cvss` skill to produce a CVSS v4.0 vector and score. Discuss severity, exploitability conditions, and any Supplemental metrics, then **wait for user confirmation** and propose it:

```
mcp__varsel__propose_cvss(input: {
  case_id: <id>, value: "CVSS:4.0/AV:.../...",
  reasoning: "..."
})
```

`cvss_v4` drives the derived score and severity bucket.

## Step 4 — Sanity check

Review the advisory critically and discuss with the user:

- **Is this a valid CVE?** Criteria: https://cna.erlef.org/cve-criteria
- **Is the vulnerable version range accurate?** You express this as commit SHAs; you verify the derived range in Step 8.
- **Is the description technically accurate?** Flag vague, wrong, or misleading claims.
- **Are the affected functions/files correct?** Inspect the repo if needed.
- **Credits**: who found it vs. who fixed it?
- **Configurations**: is it conditional on specific setup?
- **Workarounds**: genuine mitigations short of patching?

Present your assessment and proposed changes. **Wait for user confirmation before proceeding.** Do not look up the introducing commit here — that is Step 5.

## Step 5 — Find the introducing commit

Use the `/find-intro-commit` skill to get the introducing commit SHA. You need the real SHA — Varsel maps SHA → version range during derivation.

## Step 6 — Describe the affected product

Propose an **affected package** with `mcp__varsel__propose_affected_package(...)`. You state commit SHAs and program files; Varsel derives the version ranges, CPEs, and per-channel path scoping.

### Presets for OTP / Elixir / Gleam

For EEF-maintained products there is a dedicated preset tool per product —
`propose_otp_affected_package`, `propose_elixir_affected_package`,
`propose_gleam_affected_package` — that prefills vendor/product/repo/CPE and
creates the channels plus one version-boundary fact per commit:

```
mcp__varsel__propose_otp_affected_package(input: {
  case_id: <id>,
  applications: ["ssh"],              // otp/elixir: one channel per app; gleam omits this field
  introduced_commit: "<intro-SHA>",
  fixed_commits: ["<fix-SHA>", ...],  // one per maintained release line; omit if unpatched
  program_files: [
    {"path": "lib/ssh/src/ssh_sftpd.erl",
     "modules": ["ssh_sftpd"],
     "routines": ["ssh_sftpd:handle_op/4"]}
  ],
  reasoning: "..."
})
```

- **Paths are repository-root-relative.** Each rendered channel scopes files/modules/routines to its own subpath automatically (per-application prefixes are handled for you).
- `propose_otp_affected_package` / `propose_elixir_affected_package` create one `pkg:otp/<application>` channel per listed application, plus a boundary fact per commit. `propose_gleam_affected_package` takes no applications and gets its `sid` + OCI channels.
- When vulnerable code **moved between OTP applications** over time, additionally propose channel-scoped explicit `version_event`s bounding the former application's channel — the preset can't infer historical moves.

### Hex packages and everything else

For a third-party hex package or any non-preset product, propose the whole product in **one** `propose_affected_package` call — the package plus its channels and boundary facts nested inline, so a single acceptance creates all of it:

```
mcp__varsel__propose_affected_package(input: {
  case_id: <id>,
  vendor: "...", product: "...", repo_url: "...", cpe: "...",
  channels: [
    {purl_type: "hex", name: "<name>"}      // any purl type works; the repository's own channel is derived from repo_url — normally you don't list it
  ],
  version_events: [
    {event: "introduced", commit_sha: "<intro-SHA>"},
    {event: "fixed", commit_sha: "<fix-SHA>"}   // omit if unpatched
  ],
  reasoning: "..."
})
```

- State the SHAs as boundary **facts**; do not write version ranges — Varsel derives them.
- `version_events` here are **package-global**. If different channels genuinely need *different* versions from each other, don't try to model it — stop and ask the user how to proceed.
- `propose_package_channel` / `propose_version_event` (addressing the package by `target_id`) are only for extending a package that has **already been accepted** — not for the initial insert.

Notes:
- **npm mirror**: some Elixir libs (eg. Phoenix, …) ship a companion npm package. If the vulnerable file actually ships in the npm tarball (`npm pack --dry-run` to confirm; paths may differ), add a `pkg:npm/<name>` channel with its own program-file paths. If the CVE only touches Elixir/Erlang source, skip it.
- **Cross-language reachability (NIFs/BIFs)**: when the vulnerable code sits behind a language boundary, list **both sides** of the call chain in program files/modules/routines — the implementing function *and* the Erlang/Elixir wrapper callers invoke.
- **Extraction packages**: if code in package A was extracted into package B, model them as two affected packages; A's fix boundary is the extraction point, B carries the real fix commit.
- `programRoutines` list the **vulnerable** routines only (skip bookkeeping helpers the patch incidentally touched). Erlang notation `module:function/arity`; Elixir modules take the `'Elixir.ModuleName'` atom prefix.
- **Unpatched**: omit `fixed_commits` / the fix boundary. Varsel renders the open-ended range; the description and references carry `TODO`.

## Step 7 — Descriptions, metadata, references, credits

Propose the remaining fields onto the case, one typed tool per field. Each tool's description lists its exact arguments and enum values — follow it; the notes here are the editorial judgment on top.

Use correct Unicode everywhere, including full diacritics in names (e.g. `Michał Wąsowski`, `Jonatan Männchen`). Never transliterate or strip accents from a real name.

- **Description** (`propose_description`, `value`): do not mention other CVE IDs — name the vulnerability class. The "This issue affects …" sentence ends with a real version (or `before TODO` if unpatched), never a bare `TODO`.
- **Discovery** (`propose_discovery`, `value`): often already set at `open_case`.
- **Configurations** (`propose_configurations`, `value`): only if the vulnerability needs specific deployment conditions; omit when unconditional.
- **Workarounds** (`propose_workarounds`, `value`): only genuine mitigations. Never "apply the patch". Omit if none.
- **Weakness** (`propose_weakness`): use `/find-cwe`.
- **Impact** (`propose_impact`): use `/find-capec`.
- **References** (`propose_reference`, `url` + `tags`), in order: vendor advisory (GHSA → `["vendor-advisory", "related"]`), then patch commit(s) (`["patch"]`), then for OTP the version-scheme doc (`["x_version-scheme"]`). Varsel auto-adds the `cna.erlef.org` and `osv.dev` references on ID assignment — do not propose them. If unpatched, omit the patch reference entirely.
- **Credits** (`propose_credit`, `name` + `credit_type` [+ `organization`]): use the CVE schema roles by their definitions (analyst and coordinator are distinct), and give each person every role that applies — a GHSA carries only one per person. `name` is the full real name only — no handle, no affiliation — spelled with its correct diacritics. An affiliation goes in the separate `organization` field (e.g. `name: "Jonatan Männchen", organization: "EEF"`), never appended to `name`; Varsel renders `name / organization` for you. Do not skip `pending` credits.

To remove a child row, use `propose_delete` with its `target` (e.g. `"reference"`) and `target_id`.

## Step 8 — Derive and check the ranges

⚠️ **Derivation and rendering run on _applied_ (accepted) state, not on open proposals.** Everything you submitted above is an open proposal until a human accepts it in the UI. So this step only works once the affected-package proposal (at minimum) has been **accepted** — before that, there is no `affected_package` row to derive against. If proposals are still open, pause and ask the user to accept them (they may accept just the affected-package one to unblock derivation), then continue.

Once accepted, **refresh the derivation** and inspect the ranges it returns:

```
mcp__varsel__refresh_case_derivation(id: <case-id>)
```

⚠️ **Refresh recomputes; the preview does not.** `render_case_preview` renders from the *cached* derivation and does **not** recompute it, so after accepting any affected-package change you must refresh or the preview shows stale ranges — often an affected entry with **no versions at all**, flagged as a `version derivation is out of date` blocker. `refresh_case_derivation` returns the freshly rendered preview itself (the same CNA container, validation result, overrides, and blockers as `render_case_preview`), so a single refresh both recomputes and shows you the result — no separate preview call needed here.

Pass `refresh: true` when the package repository may have changed since the last derivation, most often when a fix shows as unreleased and the tag should exist by now. It refetches the repository state before deriving; without it, derivation can reuse recently cached git state and miss tags pushed in the meantime.

Confirm each affected entry's derived `from X before Y` matches the advisory's first-affected / fixed versions. A wrong range means a wrong boundary SHA — fix it with a new proposal (which again needs accepting, then another refresh, before it takes effect).

## Step 9 — Verify

Run the `/verify` skill on the case. Fix any issues as proposals and re-verify until clean.

## Done

Hand off to the user with the case ready for review: the proposals are authored, the derived ranges check out, and verification passes. Assignment, proposal acceptance, and publishing happen in the UI (a human) — the agent never self-approves proposals and does not publish.