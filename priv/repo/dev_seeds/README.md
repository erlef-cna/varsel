<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Dev seeds

Scripts that stage the dev database with data the UI needs to be looked at.
All of them are idempotent (reseeding replaces what they created) and refuse
to run outside the dev environment.

## `public_cve_matrix.exs`

A matrix of published CVE records covering every data shape the public detail
page must render. Reseeding replaces the whole `CVE-2098-*` range.

```shell
mix run priv/repo/dev_seeds/public_cve_matrix.exs
```

## `docs_screenshots.exs` + `docs_screenshots_capture.mjs`

The staging and capture pipeline behind the screenshots of this site in
`priv/static/images/guide/` (embedded by the `priv/pages/guide-*.md` pages),
`priv/static/images/maintainer-process/` (the maintainer process page) and
`priv/static/images/coordinator-process/` (the coordinator process page).
The screenshots of github.com and Slack in those two directories are captured
by hand. The seed creates the mock users in every
role, a draft case with affected package, boundary facts, a cached
derivation, open and accepted proposals, comments, an invite to `octocat`
(skipped offline), a linked draft GitHub advisory with a comment synced from
it, a second case in review, and a submitted vulnerability
report with the case it opened, with the supporter assigned. Marker: `docs-screenshots-seed` in the cases' internal notes; the
reserved CVE ID is `CVE-2026-909090`.

Regenerating the screenshots:

```shell
mix run priv/repo/dev_seeds/docs_screenshots.exs
mix phx.server           # if not already running
node priv/repo/dev_seeds/docs_screenshots_capture.mjs
oxipng -o 6 --strip safe priv/static/images/{guide,maintainer-process,coordinator-process}/*.png
```

The `oxipng` pre-commit hook refuses PNGs that are not optimized.

The capture script needs no dependencies (Node ≥ 22 plus a local Chrome,
override the binary with `CHROME_BIN`, the server URL with `BASE_URL`). It
finds the seeded case through `.docs_screenshots_manifest.json`, which the
seed writes next to itself, signs in through the mock provider per role, and
writes the PNGs straight into those directories.

The captures are safe to run against a dev database holding other data: the
triage shot searches the POC's case board down to the seeded package and the
users shot drops every non-mock account before capturing. Check a regenerated shot anyway before
committing it — a layout change can move real data into frame.
