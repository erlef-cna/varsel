<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Threat Model — Varsel

## 1. Header

- **Project:** Varsel — the CVE case-management service behind the Erlang
  Ecosystem Foundation's CNA (CVE Numbering Authority).
- **Versioning:** the model is versioned with the project (it lives in the
  repo and moves with `main`): a report against a given version is triaged
  against the model as it stood at that version. Written against `main`,
  last updated 2026-07-27.
- **Relationship to `SECURITY.md`:** this document accompanies `SECURITY.md`
  (it does not replace it). `SECURITY.md` holds the disclosure policy and a
  short Scope section that links here; this document is the detailed model.
- **Reporting:** §8 (properties provided) violations go to the disclosure
  channel in `SECURITY.md`. §3 (out of scope) and §9 (disclaimed) findings
  are closed citing this document, quoting the section.

Parenthetical file references (e.g. `(router.ex)`) point at the code a claim
rests on.

**What Varsel is.** Varsel is a Phoenix/LiveView application (Elixir, on the
Ash framework, PostgreSQL, Oban) that manages the full lifecycle of CVE
records for the BEAM ecosystem — from inbound vulnerability reports through
reservation, drafting and publication — and serves the resulting public
CVE, OSV, CWE and CAPEC data over HTML, JSON, GraphQL and MCP. It is the
authoritative CNA workbench: authenticated points-of-contact drive CVE IDs
through a state machine and, on publish, push CNA containers to MITRE's CVE
Services API. Everyone else consumes the published data read-only.

---

## 2. Scope and intended use

**Production intent.** Varsel is a production service operated by the EEF CNA
for its own use — a single-operator, single-tenant deployment, not a library
or a reusable/self-hostable product. There is one authoritative instance
(plus a test instance); it is not designed to be run by third parties against
their own CNA. Another CNA interested in the tooling is welcome to reach out,
but shared/self-hosted operation is not a supported deployment shape today.
(`README.md`)

**Primary use cases:**

- Authenticated CNA staff triage inbound vulnerability reports, build
  editorial *cases*, and publish CVE records to MITRE (`README.md`).
- The public consumes published CVE/OSV/CWE/CAPEC data **anonymously** over
  HTML pages, JSON feeds and Atom/RSS. The same data is also queryable over
  GraphQL and MCP, but those endpoints **require a login** (API key, session,
  or OAuth token) — they are not an anonymous surface. That covers all three
  GraphQL entrances: `/gql`, the playground, and the `/ws/gql` websocket.
  (`README.md`, `router.ex`, `graphql_socket.ex`)

**Deployment context.** A public-facing web service behind TLS on Fly.io,
config entirely from environment variables/secrets (`README.md`,
`runtime.exs`). HTTPS termination, network-level rate limiting, and DDoS
protection are the platform's/operator's job, not the app's.

**Caller roles.** Unlike a library, there is no single "caller." Four roles:

- **Anonymous / public** — untrusted internet clients. See only published
  data.
- **Authenticated user (no role / `nil`)** — a logged-in user with no CNA
  role, which is what every new sign-in starts as. Rights: submit a
  vulnerability report and read/withdraw their own, manage their own API keys
  and sessions, set a notification address one of their own linked providers
  reported, and run the CVE **validation** actions (§6). They are refused
  outright on `Case` — its policy is strict and admits only `:poc` and
  `:supporter`, so a role-less caller gets a refusal there rather than an
  empty list.
- **Supporter** — a CNA collaborator scoped to the specific cases they are
  assigned to. Can read and edit content on those cases; cannot run
  lifecycle actions or publish.
- **POC (point of contact)** — privileged CNA operator. Full lifecycle
  authority, including publishing to MITRE and assigning roles.

Roles live in `Varsel.Accounts.User.Role` (`:poc | :supporter`, plus `nil`)
— see `user/role.ex`.

**How someone becomes a user.** Sign-in is OAuth-only — GitHub or Hex.pm.
There is no password strategy, no magic link and no confirmation strategy on
`Varsel.Accounts.User`; the router still declares `reset_route`,
`confirm_route` and `magic_sign_in_route`, so those paths render, but with no
strategy behind them they cannot authenticate anyone. Either provider can be
left unconfigured, and a half-configured one refuses to boot.
Registration is open: anyone with an account at a configured provider becomes
an authenticated user. **The first account to register becomes POC** — the
check counts users and promotes when the table is empty, so deleting every
account re-arms it for whoever signs in next (`promote_first_user_to_poc.ex`).

### Component-family table

| Family | Entry point | Touches outside process? | In model? |
| --- | --- | --- | --- |
| Anonymous read surface (CVE/OSV JSON, HTML, feeds, sitemap) | `/cves`, `/osv`, `/`, `/feed.*`, `/sitemap.xml` | DB reads | **Yes** |
| Authenticated API (GraphQL, MCP) — login-gated even for read tools | `/gql`, `/mcp` | DB reads/writes, workbench tools | **Yes** |
| GraphQL websocket — login-gated like `/gql` | `/ws/gql` | DB reads/writes under policy | **Yes** |
| CVE validation actions — any authenticated user | `validate_cve_record*` (GraphQL + MCP) | **cvelint subprocess**, **hex.pm egress** | **Yes — §6** |
| Auth surface (GitHub **and Hex.pm** OAuth login, OAuth 2.1 server, API keys, sessions) | `/auth`, `/oauth/*`, `/sign-in`, `/settings/tokens`, `/settings/account` | GitHub + Hex.pm IdPs, DB | **Yes** |
| Account linking (attach a second provider to an existing account) | `/settings/account/link/start/:strategy` | IdP, DB | **Yes — §6** |
| CNA workbench (cases, reports, CVE lifecycle, user mgmt) — LiveView + GraphQL/MCP tools | `/cases`, `/reports`, `/users`, `/cves`, GraphQL/MCP POC tools | DB, **MITRE API**, **git egress** | **Yes** |
| Render-time derivation (`exgit` git clone/fetch of package repos) | `Varsel.Cases.Derivation` | **Outbound git to `repo_url`** | **Yes — key boundary (§4)** |
| Catalog sync (CWE/CAPEC/OTP-versions) — Oban jobs | scheduled workers | Outbound HTTPS to fixed hosts | **Yes (trusted-source egress)** |
| `cvelint` subprocess (validates rendered CVE JSON) | `Varsel.CVE.Cvelint` | `System.cmd`, temp file | **Yes** |
| Dev tooling (LiveDashboard, Oban Web, AshAdmin, Swoosh mailbox, storybook, error preview) | `/dev/*` | DB, mail | **No — §3 (absent from prod builds)** |
| Mock login (unauthenticated sign-in as a dummy user of any role) | `/auth/user/mock/callback` | DB | **No — §3 (absent from prod builds)** |
| GraphiQL playground | `/gql/playground` | DB | **Yes, but relaxed CSP — §5a** |

There is **no plugin/extension/user-defined-function loader.** Tool exposure
over MCP/GraphQL is a fixed, compile-time list (`router.ex`); there is no
dynamic code loading from any actor.

---

## 3. Out of scope (explicit non-goals)

- **Multi-tenant / third-party self-hosting.** Varsel is not built to isolate
  multiple independent CNAs on one instance; there is no tenant model
  (`no multitenancy anywhere`, verified). Reports premised on
  tenant-to-tenant isolation are out of model.
- **Attackers who already hold a POC account.** A POC is a fully trusted CNA
  operator with authority to publish to MITRE, assign roles, and reach every
  outbound integration. Threats that require *being* a POC (or convincing one
  to act) are governance/insider concerns, not product security boundaries.
- **The developer tooling under `/dev/*`** — the dashboards
  (`/dev/dashboard`, `/dev/oban`, `/dev/admin`, `/dev/mailbox`), the component
  storybook (`/dev/storybook`) and the error-page preview
  (`/dev/http-error/:status`). All of it lives in the `dev/` directory, which
  `elixirc_paths/1` compiles **only** for `:dev` and `:test`, so none of these
  modules — `VarselWeb.DevRouter`, its routes and the dev-nav component —
  exist in a production build at all. The dashboards additionally run a
  relaxed CSP; the storybook serves component fixtures, never real data.

- **The mock login** (`/auth/user/mock/callback?role=…`) — a deliberate, total
  authentication bypass that signs the caller in as a dummy user of the
  requested role (**including POC**) with no credential, so where it exists it
  **voids every §8 authorization property**. The role is a plain query
  parameter and the sign-in page links one per role; only the three roles the
  strategy declares are accepted, but that is a typo guard, not a control —
  every one of them is unauthenticated.

  It is an ordinary authentication strategy: it registers through the same
  action every provider does, and the account it creates carries a normal
  identity row, so the linking and resolution paths (§8) are exercised in
  development rather than bypassed.

  Its modules compile into every build. What confines it to development is the
  `mock do` block on `Varsel.Accounts.User` and its `register_with_mock`
  action, both behind a `Mix.env/0` check evaluated at compile time. Undeclared
  the strategy has no route and no action, so there is no way in. The guard is
  that condition, not the presence of a file; widening it is what would expose
  the bypass. There is no runtime flag and no configuration override.

  Findings against any of this are `OUT-OF-MODEL: unsupported-component`; a
  finding that a *production build declares the mock strategy* is a
  build/deployment error (§10), not a code defect.
  (`mix.exs`, `dev/`, `router.ex`, `user.ex`)
- **The `cvelint` and `exgit` third-party tools themselves.** Varsel invokes
  them; bugs *inside* them are upstream (see §6). Varsel owns only how it
  feeds them.
- **Correctness of the CVE/OSV data content.** Whether a published advisory
  is factually accurate or complete is an editorial/CNA-process matter, not a
  security property of this software.
- **Availability guarantees / SLA.** No uptime, latency, or throughput
  guarantee is made. DoS resistance is treated narrowly (§8).

---

## 4. Trust boundaries and data flow

The **primary trust boundary is authentication + role**. Every Ash resource
is guarded by `Ash.Policy.Authorizer`; the web pipelines
(`router.ex`) resolve an actor from one of three credential types (API key,
session JWT, OAuth 2.1 bearer) and every action re-applies its policy. There
is no "inside the app, everything is trusted" zone — even LiveView mounts
re-run authorization on refetch (pervasive `policies do` blocks; `config.exs`
sets `no_filter_static_forbidden_reads?: false`).

**The boundary is enforced in one place.** The router runs a single
`:live_user` hook that resolves the actor and nothing else; it does not gate
routes by role, and there is no route-level allowlist to keep in step with
the policies. A caller who requests a page they may not have reaches the
LiveView, the first action it runs refuses, and the refusal is what produces
the error page. The console's own affordances are drawn the same way — a
button appears because `Ash.can?` says the action would run, not because a
role was matched in the template. The practical
consequence for a triager: **a report that a UI element is visible to the
wrong actor is a policy question, not a routing question**, and the same
policy is what refuses the request behind it. (`router.ex`,
`live_user_auth.ex`)

**Refusal is not the only way a policy says no.** Ash policies come in two
flavours and they fail differently. A *strict* check (`actor_present()`,
`actor_attribute_equals`) is decided before any query runs and produces a
`Forbidden` error; a *filter* check (`relates_to_actor_via`,
`expr(id == ^actor(:id))`) authorizes the action and narrows the rows, so an
unauthorized caller gets an **empty result, not an error**. Both are correct
outcomes. Five strict policies exist:

- `Case`, `User`, `ApiKey` and `VulnerabilityReport` carry a resource-wide
  strict policy, so an anonymous read refuses outright rather than returning
  nothing.
- `Token` carries an action-scoped strict policy on `:list_sessions`, which
  compares the requested subject to the actor's own id.

`Case`'s strict policy is not merely "is anyone signed in": it admits `:poc`
and `:supporter` only, so **an authenticated user with no role is refused
there too**, not filtered to empty. Every other private resource (case
children, proposals, comments) is filter-scoped and returns an empty list to
an anonymous or role-less caller. Reading each
resource as an anonymous actor and as a role-less one bears this out: the
strict resources refuse, the filter-scoped ones return zero of the rows that
exist. **An "empty list" is therefore not evidence of a missing policy**, and
a report premised on a private resource returning `{:ok, []}` rather than an
error is out of model. (all `policies do` blocks)

**The websocket carries the same login requirement as `/gql`.** A socket has
no `conn`, so the `:graphql` pipeline's plugs cannot run on it. `/ws/gql`
therefore authenticates the connection itself, accepting the same three
credentials and refusing the handshake outright when none identifies a user:
an `eefcna_` API key, a session (delegated to AshAuthentication, so a revoked
or signed-out token stops working here too), or an OAuth 2.1 token that
carries the `gql` scope — a token minted for MCP is refused, exactly as on the
HTTP surface. The resolved actor is put into the Absinthe context, so policies
apply to socket-borne documents as they do to posted ones. Credentials travel
in the connect params because browsers cannot set headers on a websocket
handshake. (`graphql_socket.ex`, `endpoint.ex`)

**Data flow across the boundary:**

1. **Public read** — anonymous request → read action → policy filters to
   `state == :published` (CVE) or `always()` (OSV/CWE/CAPEC) → serialized
   JSON/HTML. No write path. (`cve_record.ex`, `osv_record.ex`)
2. **Report intake** — authenticated user → `VulnerabilityReport.submit`
   (`actor_present()`) → arbitrary `report_json` persisted → content-free
   "go look" email to POCs (Oban); the payload itself never leaves the
   authenticated console. (`vulnerability_report.ex`, `emails.ex`)
3. **Editorial** — POC/assigned-supporter → case + child rows (facts) →
   **render-time derivation clones `repo_url`** → rendered CNA container
   (`derivation.ex`, `git_repo.ex`).
4. **Publish** — POC → `request_publish` → Oban worker → **MITRE CVE
   Services API** (outbound, authenticated with CNA API key)
   (`cve_record.ex`, `mitre_cve_api.ex`).

### Reachability preconditions (the triager's first test)

For a finding to be **in model**, it must be reachable at the privilege it
claims:

- **Anonymous read surface** (HTML/JSON/feeds) — reachable from anonymous
  HTTP. A finding is in-model only if it lets an anonymous caller read a
  non-`published` record, or read a resource whose policy is not
  `always()`-public. (GraphQL/MCP expose the same reads but require a login,
  so a "public data over GraphQL/MCP" claim is really an *authenticated*-read
  claim.)
- **`repo_url` git egress** — reachable only by a **POC or a supporter
  assigned to that case** (the `AffectedPackage` create/update policy is
  `role == :poc OR relates_to_actor_via([:case, :assignments, :user])` — the
  actor is a POC, or the row's case has a `CaseAssignment` to the actor). A
  finding here that assumes an *ordinary* authenticated user or anonymous
  caller controls `repo_url` is out of model. (`affected_package.ex`)
- **Report intake** — reachable by **any authenticated user**. `report_json`
  is fully attacker-controlled at that privilege; downstream sinks (email,
  triage UI) are the question.
- **CVE validation** (`validate_cve_record`, `…_schema`, `…_cvelint`,
  `…_hex_packages`, `…_eef`) — reachable by **any authenticated user**, over
  GraphQL and MCP. These actions read nothing and write nothing: they take a
  CVE record as an argument and report what is wrong with it, so there is no
  state for a policy to protect and `Varsel.CVE.CveValidation` carries no
  authorizer. The login gate on those two surfaces is the access control.
  It is still the lowest privilege from which the **cvelint subprocess** and
  **hex.pm egress** can be driven, with fully caller-supplied JSON, so a
  finding in those sinks is in model at *authenticated-user* privilege — not
  POC.
- **Catalog sync / MITRE import** — the egress targets are compile-time
  constants (the CWE/CAPEC/OTP-versions URLs) or a single operator-configured
  endpoint (`MITRE_CVE_API_BASE_URL`); no actor picks where these requests go.
  A finding premised on an *actor controlling those URLs* is out of model.
- **CVE lifecycle writes** — POC-only. Not reachable below POC.
- **A visible button is not a reachable action.** The console decides what to
  draw by asking the same policies that authorize the request, so the two
  agree by construction rather than by upkeep. A
  finding that an affordance is *shown* to the wrong actor is in model only if
  the underlying action also runs for them; if the click is refused, the
  affordance is a cosmetic defect, not an authorization one.
  (`case_detail_live.ex`, `cve_list_live.ex`)

---

## 5. Assumptions about the environment

- **Runtime:** Elixir/OTP on the BEAM; PostgreSQL as the only datastore;
  Bandit HTTP server; Oban for background jobs. Memory-safe runtime — the
  memory-corruption class of §7 that dominates C-library models is **not
  applicable** here. (`mix.exs`, `config.exs`)
- **Deployment:** behind TLS (Fly.io); `PHX_HOST` and all secrets supplied by
  environment. In prod the app **forces HTTPS and sends HSTS**: `force_ssl`
  redirects any plaintext request and sets a 2-year `Strict-Transport-Security`
  header with `includeSubDomains` and `preload`. TLS is terminated at the
  Fly.io edge, so the original scheme is read from `x-forwarded-proto`
  (`rewrite_on`) rather than the socket. (`prod.exs`)
- **Time/clock:** the git-derivation cache and OAuth token expiry rely on a
  monotonic and wall clock respectively; no assumption beyond a
  correctly-set host clock.
- **Secrets at rest:** OAuth client secrets, GitHub tokens, and the
  `report`/case data are protected by DB access control; a Cloak/AES-GCM
  vault (`CLOAK_KEY`) is configured for `ash_cloak`-encrypted fields
  (`runtime.exs`).

**What the app does to its host (side-effect inventory):**

- **Opens outbound network connections** — yes: to MITRE (`cveawg`,
  `cwe.mitre.org`, `capec.mitre.org`), to `raw.githubusercontent.com` for the
  OTP versions table, to GitHub as the OAuth IdP, to the SMTP relay, and —
  critically — **to the public https host a case's `repo_url` names** during
  derivation (see §6).
- **Spawns a subprocess** — yes: `System.cmd("/bin/sh", …)` to run the
  `cvelint` binary; and writes a short-lived temp file with the CVE JSON
  (`cvelint.ex`).
- **Sends email** — yes, to POC addresses via SMTP. (`emails.ex`)
- **Writes to disk** — only the transient `cvelint` temp file, written into a
  fresh per-call directory and removed in an `after`; `exgit` and the catalog
  unzip are **in-memory**. The record's CVE ID names the file, and since a
  caller supplies that id, only a real CVE-ID shape is used as a filename —
  anything else falls back to a placeholder, so the write cannot leave the
  temp directory (`cvelint.ex`, `weakness.ex`, `git_repo.ex`).

**Derivation is one process for the whole node.** Every git clone, fetch and
graph walk runs inside a single named GenServer (`Varsel.Cases.Derivation.
GitRepo`), so derivation is serialized: one slow or hostile `repo_url` delays
derivation for every case until its 10-minute call timeout expires. The
timeout, the 900 s cache TTL and the 250k commit cap bound a single
derivation; they do not stop one repository from occupying the shared process.
That process also keeps a commit-object store per distinct `repo_url`,
replaced when stale but **never evicted by count**, so memory grows with the
number of distinct URLs derived. Both are bounded in practice by the
POC/assignee privilege needed to add a package (§9). (`git_repo.ex`,
`application.ex`)

### 5a. Build-time and configuration variants

| Knob | Default | Effect on model |
| --- | --- | --- |
| `MIX_ENV` (compile) | `prod` for releases | The **only** switch governing the `/dev/*` tooling and the mock login (§3), through two mechanisms. `elixirc_paths/1` adds the `dev/` directory for `:dev` and `:test` only, so a prod build contains neither `VarselWeb.DevRouter` (dashboards, storybook, error preview) nor the dev-nav component. The mock login is instead gated by `Mix.env/0` checks *inside* `Varsel.Accounts.User`, which drop the `mock do` strategy declaration and the `register_with_mock` action — its modules compile, but nothing declares them, so there is no route and no action. The storybook, Oban Web and LiveDashboard **dependencies** are themselves `only: [:dev, :test]`, so a prod build cannot link them even by mistake. There is no runtime or configuration override — building with `MIX_ENV=prod` is the whole control. **A release built from any other env exposes an unauthenticated POC sign-in and this model no longer holds at all.** (`mix.exs`, `dev/`, `user.ex`) |
| `TEST_DEPLOYMENT` (runtime) | `true` | When true, serves a disallow-all `robots.txt`, `X-Robots-Tag: noindex`, and a warning banner. **Must be set `false` on the real production instance.** Not a security control — an indexing/labeling one. (`config.exs`, `runtime.exs`) |
| `MITRE_CVE_API_BASE_URL` | none (required) | Points the publish pipeline at a MITRE endpoint. Every configured endpoint (including MITRE's shared staging, `cveawg-test`) is a real remote system — the pipeline has no in-app dry-run or sandbox, so any publish leaves the machine (see §9, "false friend"). (`mitre_cve_api.ex`) |
| GraphiQL relaxed CSP | route-scoped | `/gql/playground` serves `'unsafe-inline'` + a jsdelivr allowlist so GraphiQL boots. The rest of the site is deny-by-default (`default-src 'none'`, `script-src 'self'`, nonce'd). In a prod build this is the *only* CSP relaxation, and it is confined to that one login-gated route (the `/dev/*` relaxation lives in `VarselWeb.DevRouter`, which is not compiled). (`router.ex`, `dev/dev_router.ex`) |

One build variant voids the §8 auth properties outright — a non-`prod`
`MIX_ENV`, which ships the mock login: an intentional authentication bypass.
It fails loudly rather than silently: there is no runtime or environment
override that can enable it in a `prod` build (the strategy is not declared,
the `/dev/*` code is not compiled, and its dependencies are not even linked),
and where it *is* present the sign-in page lists it beside the real
providers and every page carries a visible floating dev-tools launcher. The
two variants that matter (a release built from a non-`prod` env,
`TEST_DEPLOYMENT` left true) are operator-deployment errors, surfaced in §10.

---

## 6. Assumptions about inputs

**Default trust posture.** All Ash action parameters are treated as
attacker-controlled at the privilege of the actor allowed to call the action;
Ash validates types and the policies gate who calls what. The exceptions
worth tabulating — where the *content* of an input reaches a sensitive sink —
are below.

| Surface | Parameter | Attacker-controllable? | Sink / caller must |
| --- | --- | --- | --- |
| `VulnerabilityReport.submit` | `report_json`, `report_body`, `summary` | **Yes — any authenticated user** | Persisted (size-capped, default 256 KiB); triage UI (escaped, §7/§8). The POC email is content-free (link only), so the payload never leaves the authenticated console. |
| `AffectedPackage` create/update | `repo_url` | **Yes — POC / assigned supporter only**; constrained to `https://` and to a host that resolves to a public address | `Exgit.clone(repo_url)` → outbound https git egress to a public host (§4, §9) |
| `VersionEvent` | `commit_sha` | Yes — POC / assigned supporter | Regex-constrained to hex SHA before git use (`affected_package.ex`) |
| `CveRecord.request_publish` / `update` | `cve_json` (CNA container) | POC only | Validated (`ValidCveRecord`, cvelint, schema) then pushed to MITRE |
| `CveValidation.validate*` | `cve_json` | **Yes — any authenticated user** | **cvelint subprocess** (temp file; argv, not shell; filename constrained to a CVE-ID shape) and **hex.pm lookups** keyed on package names taken from the JSON. No policy authorizer on this resource; the login gate is the control (§4) |
| `Case.cna_override` | RFC 7396 merge patch on rendered container | POC / assigned supporter | Applied as last render step; can override any rendered field (`case.ex`) |
| GitHub OAuth | `user_info` (sub, preferred_username, name, email) | IdP-supplied, verified by GitHub | Stored as `github_id/handle/name/email`; `handle` later in a client-side `img`/link |
| Hex.pm OAuth | `user_info` (username as `sub`, email) | IdP-supplied by Hex.pm | Identity keyed on the **username**, since Hex.pm exposes no numeric id and offers no way to rename an account (§7). Email is opt-in-public there, so it is usually absent and is never used to match an account |
| Account linking | `:strategy` path segment; `linking_from_user_id` **from the session** | Any authenticated user | Names the account by id from the signed session, not from `current_user`. Linking an identity another account already owns is refused (`resolve_oauth_identity.ex`) |
| MCP/GraphQL tool args | per tool | scope-gated bearer (mcp/gql) + role policy | Same Ash actions as above; no separate trust level |

**Persisted state as input.** Varsel reads back only its own PostgreSQL rows
(guarded by policies) and its in-memory caches. It does **not** deserialize an
on-disk project file, session blob, or user-writable data directory on
startup, so the "opening a file executes code" class does not apply. The one
externally-fetched artifact re-read across runs is the CWE/CAPEC catalog and
the OTP versions table — all from fixed MITRE/GitHub hosts (§6a/§6b), not
attacker-writable.

**Size / rate.** `report_json` is free-form JSON from any authenticated user,
now **capped** at a configurable serialized size (default 256 KiB,
`:max_report_json_bytes`) via the `ReportJsonSize` validation — a single
oversized payload is rejected, though submission *rate* is still unbounded
in-app (§9, operator's edge). Git derivation fetches an entire commit graph
(`tree:0`, no blobs) from `repo_url`, bounded by a 10-minute GenServer timeout,
a 900s cache TTL, and a 250k commit-count cap on the graph walk
(`report_json_size.ex`, `git_repo.ex`).

### 6a. Outputs and expected sinks

| Output | Expected sink | Sink-safe? | If not, caller must |
| --- | --- | --- | --- |
| Case markdown → on-site HTML (`Markdown.to_display_html`) | Browser HTML | **Yes** — rendered `unsafe: true` then run through the `sanitize` (ammonia) allow-list, so scripts/handlers/dangerous URLs are stripped while safe author HTML survives (`markdown.ex`) | — (sanitized) |
| Case markdown → `supportingMedia` text/html in published CVE (`Markdown.to_html`) | MITRE + downstream CVE consumers | Yes — same sanitized Comrak output | — |
| CVE record prose → on-site HTML (`cve_view.ex` `prose/2`) | Browser HTML | **Yes** — `markdown/1` sanitizes its output; a `supportingMedia` HTML value (may be MITRE-imported) is run through `MDExNative.Ammonia.safe_html/1` before render (`cve_view.ex`) | — (sanitized) |
| CVE JSON / OSV JSON | Machine consumers, cross-origin | N/A (data) — CORP dropped deliberately for these (`public_resource.ex`) | — |
| Atom/RSS feeds | Feed readers, cross-origin | **Yes** — built as an XML tree and encoded (`Saxy`), never concatenated, so every value is escaped as text or as an attribute by construction. Links are `~p` routes resolved against the endpoint, so they name the configured host and the request's `Host` never reaches the document (`feed_controller.ex`) | — |
| Sitemap XML | Crawlers | **Yes** — same as the feeds: an XML tree, encoded (`Saxy`). The host is the configured `Endpoint.url()`, not the request's (`sitemap_controller.ex`) | — |
| `avatar_url` on a user | Browser `img` | Public field, deliberately. With a linked GitHub account it is that account's picture; otherwise a Gravatar URL keyed on the MD5 of `notification_email`, which lets anyone who can read the row test a guess at that address (§9) (`user.ex`) | — |
| POC notification email | Plain-text mail | Yes — `text_body`, fixed headers, and **content-free**: it carries only a link to the authenticated triage console, no report payload or reporter identity, since email is unencrypted in transit/at rest (`emails.ex`) | — |
| Published CNA container → MITRE API | MITRE (trusted) | JSON body; MITRE is trusted sink | — |

Every markdown/HTML render sink now sanitizes (ammonia allow-list) before
`raw/1`, so injected script/handlers are stripped at the source. The app-wide
**strict CSP** (`default-src 'none'`, `script-src 'self'` with per-request
nonce, **no `unsafe-inline`/`unsafe-eval`**) is a second, independent layer:
even a sanitizer bypass would need an inline `<script>`/event handler the
browser refuses. (`config.exs`) In a prod build the only CSP relaxation is
`/gql/playground`, which is login-gated and serves no user-authored content;
the `/dev/*` relaxation compiles out (§5a).

### 6b. Delegated and inherited surface

**Policy: a vulnerability in a dependency is the dependency's vulnerability.**
Varsel does not re-export any dependency's API as its own security surface, so
a bug inside a linked, vendored, or shelled-out-to dependency is reported
upstream and fixed here by **updating the dependency once a fix is
released** — nothing more. There is no per-dependency ownership adjudication
to make. Patch status, pinning, and provenance are **build hygiene, out of
scope** per §1.

For orientation only, the dependencies that receive attacker-influenced input
(so an upstream bug is actually *reachable* through Varsel, rather than dead
code) are `exgit` (git data from a case's `repo_url`) and `mdex` (author
markdown / CVE prose). `saxy`, `cvelint`, and `req` are fed only trusted or
fixed-host data, so their surface is not attacker-reachable. This list informs
prioritization of a dependency bump; it does not change the disposition, which
is always `OUT-OF-MODEL: report-upstream`.

---

## 7. Adversary model

- **Anonymous internet client.** Can send arbitrary HTTP to every public
  route, attempt auth, and read published data. Cannot reach any non-public
  read or any write. The primary in-scope adversary for the read surface and
  the auth surface.
- **Authenticated user (no CNA role).** Everything the anonymous client can
  do, plus: submit vulnerability reports (arbitrary `report_json`) and manage
  their own API keys. The primary in-scope adversary for report intake and
  the token/OAuth surface. Assumed to try: privilege escalation to
  supporter/POC, reading other users' data (reports, cases, PII), forging
  another reporter's identity, exhausting storage via unbounded reports.
- **Malicious / compromised supporter.** A CNA collaborator assigned to at
  least one case. Can read and edit content on assigned cases — including
  setting `repo_url` to drive server-side git egress (§4). Assumed to try:
  reaching cases they are *not* assigned to, self-promotion, self-assignment
  (blocked — `CaseAssignment` create is POC-only), and abusing `repo_url` for
  SSRF-style egress. **In scope** as a distinct actor.
- **Byzantine OAuth client (MCP/GraphQL).** A registered OAuth 2.1 client
  (DCR is enabled) presenting a bearer token. Bounded by the token's scope
  (`mcp` vs `gql`, enforced per surface) and the underlying user's role.
  Assumed to try: using a token minted for one surface on another (blocked by
  scope enforcement, `oauth_bearer_auth.ex`), or exceeding the user's role
  (blocked by Ash policies). **In scope.**

**Explicitly out of scope:**

- **A POC.** Trusted CNA operator; being a POC *is* the top of the trust
  model. A malicious POC has already won (they can publish to MITRE directly).
- **Anyone who controls the MITRE API, the GitHub or Hex.pm IdP, or the SMTP
  relay.** These are trusted integration partners; compromising them is out of
  layer. Two consequences follow, and both are load-bearing:
  - **A provider's `sub` is the account key.** For Hex.pm that subject is the
    **username**: Hex.pm exposes no numeric id, and offers no way to rename an
    account, so the username is the stable identifier available. Should
    Hex.pm ever add renaming, or re-issue a deleted account's name, the
    identity row would silently re-point and whoever took the name would sign
    in as the original account — the app cannot detect that on its own. This
    is a property of the provider we rely on, so a report resting on it is
    escalated rather than closed.
  - **Email never selects an account.** Neither provider's address is trusted
    as verified, so an address is only ever a notification target.
- **An attacker with database or host access.** Beneath the app's boundary.
- **A network attacker without TLS-break capability.** TLS is assumed intact
  (terminated at the edge).

The in/out-of-scope actor boundaries above — supporter in scope (including
reaching *other* cases and self-promotion), POC out of scope as the top of
trust — are maintainer-confirmed.

There is **no plugin author** actor (no plugin surface) and **no co-tenant**
actor (single-tenant); both are N/A rather than in/out.

---

## 8. Security properties the project provides

Stated as a delta from the BEAM/Ash baseline (memory safety, type checking,
and default-deny authorization are runtime/framework-provided and not
restated as Varsel claims). Every property below is claimed for a **default
build** (`MIX_ENV=prod`) — a build that ships the mock login (§5a) provides
none of the authorization properties, by construction rather than by defect.

1. **Role-scoped authorization on every resource.**
   Every action is policy-gated; the role→action matrix in §2 holds. No
   exposed action grants callers `authorize?: false`: outside tests the flag
   is banned by the `AshCredo.Check.Warning.AuthorizeFalse` credo check
   (`.credo.exs`), so the few remaining uses are all internal
   changes/validations/notifiers, never a caller-reachable contract. Internal
   system operations that legitimately bypass the actor's policy do so through
   a bypass the actor cannot reach — the `AshObanInteraction` bypass for Oban
   jobs (a caller cannot forge the `ash_oban?` context) or an `accessing_from`
   policy for rows only ever written through a managed relationship.
   - *Violation symptom:* an actor performs an action, or reads a row/field,
     the matrix forbids (e.g. a supporter approves a case, an anonymous
     client reads a `draft` CVE, a non-POC reads another user's email).
   - *Severity:* `critical` (auth bypass / privilege escalation) for writes
     and lifecycle; `high` (information disclosure) for cross-actor reads.
   - (all `policies do` blocks)

2. **Publish authority is POC-only and cannot be reached below POC.**
   Only a POC can move a CVE toward MITRE (`request_publish`, `update`,
   `reject`) or a case toward publication (`approve`, `publish`). The Oban
   worker actions that actually call MITRE (`:publish`, `:push_update`,
   `mark_published`) are reachable *only* through the AshOban bypass — never
   from a request.
   - *Violation symptom:* a non-POC causes a write to MITRE, or an
     un-approved case reaches `publishing`.
   - *Severity:* `critical`.
   - (`cve_record.ex`, `case.ex`)

3. **A CVE ID is taken once, and only while the case can still use it.**
   `assign_cve_id` refuses a case that already holds an ID and one that is
   published or closed, so a reserved identifier cannot be silently consumed
   by a case that has no further use for it. The rule is an action validation
   rather than a precondition inside the change that performs the assignment,
   which is what makes it hold for every caller — the console, GraphQL, MCP —
   and not only the one that happens to hide the button *(maintainer,
   2026-07)*.
   - *Violation symptom:* a reserved ID is attached to a published or closed
     case, or a second ID replaces one already assigned.
   - *Severity:* `medium` (identifier waste and a misleading record, not a
     disclosure).
   - (`case.ex`, `cve_id_assignable.ex`)

4. **Field-level PII redaction on `User`.**
   A non-POC who reaches a `User` row through a permitted relationship sees
   the attribution fields — `:name`, `:github_username`, `:hex_username`,
   `:display_name` and `:avatar_url`; `:notification_email`,
   `:identity_emails` and `:role` are POC-or-self. Usernames and the picture
   are public attribution (a credit renders them), the addresses and the role
   are not. Note the avatar can confirm a *guessed* address for an account
   with no linked GitHub, which is accepted (§9). This is the second of two
   layers: the row-level read policy already removes users the actor may not
   see, so a non-POC listing users directly gets an empty result rather than
   redacted rows.
   - *Violation symptom:* a non-POC reads another user's address or role.
   - *Severity:* `high`.
   - (`user.ex`)

5. **Case content is confined to assigned collaborators.**
   Reads and edits of a case and all its child rows require POC or a
   `CaseAssignment` for that case; supporters cannot self-assign (assignment
   create/destroy is POC-only).
   - *Violation symptom:* a supporter reads or edits a case they are not
     assigned to.
   - *Severity:* `high` (unpublished advisory content is embargoed).
   - (`case.ex`, `case_assignment.ex`)

6. **OAuth scope separation between surfaces.**
   An OAuth 2.1 access token carries a scope (`mcp` or `gql`); a token
   without the required scope for a surface gets `403 insufficient_scope`.
   API keys and session JWTs (first-party credentials) are exempt by design.
   This holds on the websocket too: `/ws/gql` refuses a token that lacks the
   `gql` scope (§4).
   The property constrains **use per surface, not issuance**: a token may
   legitimately carry both scopes, and holding both is not a violation. The
   token never exceeds the underlying user's role either way. Audience does
   not separate the two surfaces — `resource_url` is the bare host — so the
   scope check is what divides them.
   - *Violation symptom:* a `gql`-scoped token invokes an MCP tool, or vice
     versa.
   - *Severity:* `high`.
   - (`oauth_bearer_auth.ex`)

7. **API keys and tokens stored hashed / redacted.**
   Only a SHA-256 hash of an API key is persisted; the plaintext is shown
   once. Token `jti` and key hashes are `sensitive?`; error redaction is on
   (`redact_sensitive_values_in_errors?: true`).
   - *Violation symptom:* a recoverable key/secret appears in the DB, a log,
     or an error response.
   - *Severity:* `high`.
   - (`api_key.ex`, `token.ex`, `config.exs`)

8. **A user sees and ends their own sessions, and only their own.**
   `/settings/account` lists the account's unexpired sign-in tokens and
   revokes them individually or all but the current one. The `:list_sessions`
   policy compares the requested subject to the actor's id, so a POC reaches
   another user's sessions no more than a stranger does. Revocation flips the
   stored row's purpose, which the session lookup then rejects. The session
   making the request is shown but never revocable, hand-made events
   included.
   **Where this one is enforced is the exception to §4.** Revocation runs
   through AshAuthentication's own token action, which takes a `jti` and
   revokes it; `Token` carries only the AshAuthentication bypass, so no policy
   narrows it. What scopes it to the caller is the account page, which refuses
   any `jti` absent from the strictly-scoped list it just read. Only three
   places revoke at all, and none takes a `jti` from a caller: the account
   page (checked as above), sign-out (the jti of the session making the
   request), and account deletion (every token of the account being deleted).
   None is exposed over GraphQL, MCP or the JSON API. So a triager checking
   this property reads those call sites rather than a policy, and any *new*
   caller of `revoke_jti` would have to bring its own check.
   Signing out revokes the token rather than only clearing the cookie.
   Each row records the user agent and IP it was created from — **personal
   data**, kept until the token expires or is expunged, deleted with the
   account, readable by its owner alone. The user agent is a client string
   and claims nothing verifiable. The address is resolved from
   `x-forwarded-for` only when the peer is a trusted proxy
   (`VarselWeb.Plugs.ClientIp`); a caller reaching the endpoint directly is
   recorded by its own address, whatever it puts in the header. `RemoteIp`
   alone would not do this — it classifies the forwarded addresses and never
   the peer.
   - *Violation symptom:* one user lists or revokes another's sessions; a
     revoked token still authenticates; sign-in details readable by anyone
     but their owner.
   - *Severity:* `high` (session-fixation-adjacent / PII disclosure).
   - (`token.ex`, `sign_in_details.ex`, `record_sign_in_details.ex`,
     `client_ip.ex`, `account_settings_live.ex`)

9. **Stored-content rendering is sanitized before display.**
   Every markdown/HTML render sink — case/report markdown
   (`Markdown.to_html`/`to_display_html`), CVE-record prose
   (`cve_view.ex` `markdown/1`), and imported `supportingMedia` HTML
   (`MDExNative.Ammonia.safe_html/1`) — passes through the ammonia allow-list
   before `raw/1`, stripping scripts, event handlers and dangerous URLs while
   keeping safe author HTML. The strict app-wide CSP (`script-src 'self'`, no
   `unsafe-inline`) is an independent second layer.
   - *Violation symptom:* stored XSS — content executes script in a viewer's
     session.
   - *Severity:* `critical` if it fired; mitigated to `low` residual by the
     sanitizer + CSP.
   - (`markdown.ex`, `cve_view.ex`, `config.exs`)

   **The XML surfaces are structurally safe.** The Atom and RSS feeds and the
   sitemap are built as an XML tree and handed to an encoder (`Saxy`); no
   markup is concatenated anywhere in them. Every value lands as a text node
   or an attribute and is escaped by construction, so neither an advisory
   title nor a summary can close a tag or open an attribute. Their links are
   `~p` routes resolved against the endpoint, so nothing from the request
   reaches either document.
   - *Violation symptom:* a value from a record or a request appears as
     markup in a feed or the sitemap, or either document fails to parse.
   - *Severity:* `high` (XML injection into a syndicated document).
   - (`feed_controller.ex`, `sitemap_controller.ex`)

10. **Report intake is size-bounded.**
   `report_json` (the one unbounded authenticated write) is capped at a
   configurable serialized size (default 256 KiB); an oversized payload is
   rejected before persistence.
   - *Violation symptom:* an authenticated user stores an arbitrarily large
     payload.
   - *Severity:* `moderate` (storage/DoS).
   - (`report_json_size.ex`)

11. **CSRF / clickjacking / cross-origin hardening on the browser surface.**
   `protect_from_forgery` on browser pipelines; `x-frame-options: DENY` +
   `frame-ancestors 'none'`; `permissions-policy`, COOP `same-origin`, CORP
   `same-site` (dropped only for the public JSON/feed data by design).
   - *Violation symptom:* a cross-site POST is accepted, the app is framed,
     or a private response is fetched cross-origin.
   - *Severity:* `high`.
   - (`router.ex`, `security_headers.ex`, `public_resource.ex`)

12. **Git egress reaches only a public address, at the moment it connects.**
   A `repo_url` is constrained to `https://` and to a host resolving publicly
   when it is saved. The clone re-resolves and re-checks immediately before
   connecting, then **pins to what that lookup returned**: the request goes to
   the address, while the hostname is kept for the `Host` header, the TLS
   server name, and the name the certificate must match. There is no second
   lookup in between for DNS to answer differently, so a name that answers
   publicly at save time and privately later is refused rather than cloned.
   Redirects stay off, so there is no later hop to re-resolve. Pinning does
   not weaken TLS: a certificate that does not match the case's hostname
   still fails the handshake.
   - *Violation symptom:* a clone connects to a loopback, RFC 1918, or other
     non-public address; or a pinned request accepts a certificate that does
     not match the named host.
   - *Severity:* `high` (server-side request forgery).
   - *Bound:* the privilege to set `repo_url` is POC or assigned supporter
     (§4), and the host may still be any *public* one — that is deliberate
     (§9).
   - (`pinned_transport.ex`, `repo_url_https.ex`, `private_address.ex`)

13. **Caller-supplied content stays inside the temp directory it is written
   to.** `cvelint` needs the record on disk, so validation writes one — into a
   fresh per-call directory, removed afterwards. The record names that file,
   and since the record comes from any authenticated user, only a real CVE-ID
   shape is used; anything else falls back to a placeholder. Nothing a caller
   supplies reaches a shell: the command is fixed and every other value is
   passed as an argument.
   - *Violation symptom:* a write lands outside the per-call directory, or a
     caller-supplied string is interpreted by the shell.
   - *Severity:* `critical` (arbitrary write / command execution).
   - (`cvelint.ex`)

14. **One provider cannot take over an account made with another.**
   An identity is matched on `(strategy, sub)` and never on an email address.
   A sign-in whose identity is unknown, but whose address another account's
   identity already reports, is **refused** rather than merged — and a
   database exclusion constraint enforces the same rule, so two concurrent
   callbacks cannot race past the check. During a link, an identity another
   account already owns is refused as well. The last provider on an account
   cannot be unlinked, since providers are the only way in.
   - *Violation symptom:* signing in with provider B lands in an account
     created with provider A, or a link moves an identity between accounts.
   - *Severity:* `critical` (account takeover).
   - *Bound:* this rests on the provider's `sub` being stable and
     non-reusable — for Hex.pm, on it offering no rename (§7).
   - (`resolve_oauth_identity.ex`, `user_identity.ex`)

**Resource bound (the one quantified DoS line we can state):** guardrails are
the git-derivation timeout (10 min), cache TTL (900 s), and 250k commit-count
cap, the Oban `Lifeline` rescue (30 min) for orphaned jobs, the `report_json`
size cap (default
256 KiB, property 10), and `max_length` caps on every free-text/markdown field
(title 500; `*_md`/comment/notes 20–50 KB; report body 200 KB) that bound the
parser input. There is still **no application-level request-rate limit** — so
submission *rate* and read-endpoint volume are not bounded in-app, and
"bounded resource use" is **not** a general claim (§9).

---

## 9. Security properties the project does *not* provide

- **No rate limiting or request-volume DoS defense at the application layer.**
  Report submission, search queries (full-text `tsquery`), and read endpoints
  are not rate-limited in-app; the operator/platform must provide it. Payload
  *size* is capped (property 10), but an authenticated user can still submit
  arbitrarily many capped `report_json` payloads. Accepted as the operator's
  edge responsibility for now; in-app rate limiting is planned (§14).
- **No allowlist on which public host `repo_url` may name.** `repo_url` is
  constrained to `https://` (rejecting exgit's `file://` local-file read and
  plaintext `http://`) and to a host that resolves to a public address —
  loopback, RFC 1918, link-local, unique-local, CGNAT and other special-use
  ranges are rejected, so a case editor cannot aim egress at an internal
  service — checked when the URL is saved and again when the clone connects
  (property 12). Beyond that the host is unrestricted on purpose, since a
  public self-hosted forge is a supported source: derivation will clone any
  public https host a POC/assignee names.
  Credentials in the URL (`https://user:token@host/…`) and non-standard ports
  are likewise accepted; the check is on the scheme and the resolved address,
  not the rest of the URL.
- **A user's identity is not treated as secret from other users.** Whoever can
  read a user row sees the display identity — name, provider usernames,
  avatar. Only the address, the linked-provider addresses and the role are
  POC-or-self. One consequence is deliberate rather than overlooked: an
  account with no linked GitHub gets a Gravatar avatar keyed on the MD5 of its
  notification address, so a viewer can test a guess at that address against
  it. It confirms a guess, it does not reveal an unknown address, and the
  people who can read a given row are the CNA collaborators already working
  the same cases. Serving the picture through the app would only move the
  hash into a redirect, and proxying it would put a fetch to a third party on
  every avatar — neither is worth it for that.
- **No availability/uptime guarantee.**
- **Nothing bounds how much outbound traffic an authenticated user can drive.**
  The validation actions reach hex.pm, and derivation reaches a case's
  `repo_url`; neither is rate-limited in-app, so Varsel can be used to push
  volume at a third party. The per-call bounds (§8) limit a single request,
  not how many are made. Same disclaimer as request-volume DoS: it is the
  operator's edge.
- **Nothing bounds how many rows an authenticated user can create for
  themselves.** API keys and sessions have no per-user cap; the §8 caps bound
  the *size* of what is stored, never the count. This is the same disclaimer
  as request-volume DoS.
- **`cna_override` is an intentional escape hatch, not a validated surface.**
  A POC can override any rendered CNA field via a merge patch; correctness of
  the result is the POC's responsibility.

**False friends — features that look like a security boundary but are not:**

- **MITRE's staging endpoint (`cveawg-test`) is not a sandbox.** It is a
  shared, real remote system; a publish against it mutates a real record.
  The pipeline has no in-app dry-run, so no configured endpoint is a safe
  rehearsal target. (`mitre_cve_api.ex`)
- **`TEST_DEPLOYMENT`'s `robots.txt`/noindex is an indexing hint, not access
  control.** It does not restrict who can read the instance — only whether
  crawlers should index it.
- **CORP being *dropped* on the JSON/feed endpoints is intentional openness,
  not a missing header.** Those responses are public data meant to be fetched
  cross-origin. (`public_resource.ex`)
- **`/ws/gql` authenticating a connection is not the router doing it.** The
  socket enforces the login requirement in its own `connect/3`, not through
  the `:graphql` pipeline, which cannot run there (§4). A change to that
  pipeline does not change the socket.
- **The account-link confirmation is the provider's consent screen, not
  ours.** Starting a link redirects straight to the provider; there is no
  in-app confirmation step, and the existing session is not re-authenticated
  before a new sign-in path is added to the account. The marker naming the
  account also has no expiry: a link abandoned at the provider leaves it in
  the session, so the next sign-in in that browser is still treated as a link
  to the same account. It is cleared on both success and failure.

**Well-known attack classes for this category, left to the caller/operator:**

- **DoS by request volume / large payloads** (see above) — operator's edge.
- **OAuth 2.1 / DCR abuse** (open dynamic client registration) — a Byzantine
  client can register; scope + role enforcement bound what it can do, but
  registration itself is open by design to support AI/MCP client integration
  (`dcr_enabled?: true`). (`oauth2_server.ex`)

---

## 10. Downstream responsibilities

Here "downstream" means the **CNA operator/deployer** (there is no library
integrator — Varsel is a deployed service).

1. **Set `TEST_DEPLOYMENT=false`** on the real production instance (defaults
   to `true`, which noindexes the site). (see §5a)
2. **Always build releases with `MIX_ENV=prod`** — it is the single control
   keeping the `/dev/*` tooling and the mock login out of the build (§5a).
   Any other env ships a full authentication bypass that lets an anonymous
   caller become a POC, plus the dashboards' relaxed CSP. Do not add the
   `dev/` directory to `elixirc_paths/1` for other environments, do not move
   those routes into `VarselWeb.Router`, and do not widen the `Mix.env/0`
   condition guarding the `mock` strategy on `Varsel.Accounts.User`. Verify on
   the built release: it must expose no `/dev/*` route and no
   `/auth/user/mock/*`.
3. **Terminate TLS at the edge and forward the scheme** — the app forces
   HTTPS + HSTS itself (`force_ssl`), but relies on the proxy setting a
   truthful `x-forwarded-proto`; a proxy that lets a client spoof it to
   `https` would defeat the redirect. `x-forwarded-for` is read on the same
   assumption, but only from a peer in the private ranges
   (`VarselWeb.Plugs.ClientIp`) — a deployment fronted from a public address
   must name it in that plug's `:proxies`, or every request will be recorded
   as coming from the proxy.
4. **Provide request rate limiting and payload-size limits at the edge** —
   the app does not (report intake, search, reads).
5. **Keep the MITRE/GitHub/SMTP credentials and `CLOAK_KEY` /
   `*_SIGNING_SECRET` out of source and rotate on schedule** — all are
   environment secrets.
6. **Grant the POC role deliberately.** POC is full publish authority; the
   first login through any configured provider auto-becomes POC (bootstrap),
   so control who logs in first. The check is "are there no users", not "has
   this ever run" — so if every account is deleted, the next person to sign in
   becomes POC again. (`user.ex`)
7. **Treat `repo_url` on cases as a trusted-egress control:** only assign
   supporters to cases you trust to set outbound clone targets. The app keeps
   that egress on public addresses and pins each clone to the address it
   checked (property 12), but any *public* host is allowed by design — so
   restrict which ones at the network layer if that matters (§9).
8. **Do not publish from a non-production instance** expecting a sandbox —
   the test MITRE endpoint is real staging (§9).

---

## 11. Known misuse patterns

- **Treating any configured MITRE endpoint as a sandbox.** The publish
  pipeline has no dry-run. *What it looks like:* pointing
  `MITRE_CVE_API_BASE_URL` at staging and running a publish to "test" the
  flow. *Why unsafe:* every publish leaves the machine and mutates a real
  record at whichever endpoint is configured. *Instead:* exercise the flow
  against a mocked MITRE client; lifecycle up to `approved` never calls MITRE.
- **Pointing `repo_url` at an internal host.** A case editor trying to aim
  server-side egress at an internal service. *Why unsafe:* would reach hosts
  behind the app's network boundary. *Blocked by:* the https-only constraint
  plus the public-address check, which rejects any `repo_url` whose host
  resolves to a private/internal range — on top of the POC/assignee privilege
  bound.
- **Assuming `cna_override` output is validated.** It is a raw merge patch;
  a POC can produce a malformed/non-standard container. *Instead:* rely on the
  `ValidCveRecord`/cvelint/schema validation that still runs on
  `request_publish`.
- **Treating a supporter as low-trust.** A supporter assigned to a case can
  read embargoed advisory content and drive git egress; assignment is a
  meaningful grant, not a read-only role.

### 11a. Known non-findings (recurring false positives)

Sobelow/credo suppressions are each documented at the suppression site —
inline `sobelow_skip` with a reason, plus `.sobelow-skips`/`.sobelow-conf` — so
a triager who hits one of those flags sees the justification there. The one
model-level recurring flag, the SSRF shape of `Exgit.clone(repo_url)`, is
addressed in §9: `repo_url` is constrained to https + a public-resolving host,
and the residual is a POC/assignee privilege — `VALID` only if shown reachable
below that privilege.

Two shapes an automated reviewer reliably mistakes for missing authorization,
both explained in §4:

- **"Route X has no authentication check."** No route does. The router
  resolves an actor and stops; the policy on the first action the page runs is
  the check. Grepping the router for a role gate finds nothing by design.
- **"Reading resource X as an anonymous caller returns success."** For a
  filter-scoped resource it returns `{:ok, []}` — success with no rows, which
  is how an Ash filter policy denies. `NOT-A-FINDING` unless rows actually
  come back, and none do.
- **"`authorize?: false` appears in the code."** Every remaining use is inside
  a change, validation or notifier that runs *after* the enclosing action's
  policy has already admitted the caller; none sits on a path a caller
  selects. Caller-facing uses are banned by a credo check (§8, property 1).
- **"The `cvelint` call shells out with user input."** It runs `/bin/sh -c`
  with a fixed script and passes everything else as argv, so no caller string
  reaches a shell parsing context. The record's CVE ID names the temp file and
  is constrained to a CVE-ID shape before use (§5).
- **"A supporter can resolve proposals like a POC."** Accepting or declining a
  proposal on an assigned case is intended supporter authority; assignment is
  the grant (§11, "treating a supporter as low-trust").
- **"A token carries both the `mcp` and `gql` scopes."** Not a scope-separation
  violation: property 6 constrains what a token may *use*, per surface, not
  what it may be issued.
- **"An avatar URL exposes the MD5 of a user's email."** Known and accepted
  (§9): a Gravatar hash confirms a guessed address to someone who can already
  read that user's row, and display identity is not secret between
  collaborators. Reported regularly because the hash is recognisable.

**An entry here describes an outcome, not a promise to disregard the
evidence.** Each says what the code does and why the flag is expected. A
report that *demonstrates* the stated control does not hold — a filename that
escapes the temp directory, an anonymous read that returns rows — is `VALID`,
not `KNOWN-NON-FINDING`. Match on the behaviour, not on the shape of the
report.

---

## 12. Conditions that would change this model

- Adding a **plugin/extension/webhook** surface, or any dynamic code/tool
  loading (today the MCP/GraphQL tool list is fixed).
- Making Varsel **multi-tenant** or self-hostable by third-party CNAs.
- Accepting a **new attacker-controllable input** that reaches a subprocess,
  a network egress, or an unsafe render sink — especially any new consumer of
  `report_json` beyond email/triage, or any new `unsafe: true` render path.
- Implementing any **§14 planned follow-up** — each promotes a §9 disclaimer
  toward a §8 property.
- **Adding a GraphQL subscription.** None is declared today, so `/ws/gql`
  carries no live data path; adding one puts pushed data on a transport whose
  authentication is written by hand rather than inherited from the router
  (§4).
- **Adding a third login provider**, or changing what a provider's `sub` means
  — account identity rests on that value being stable and non-reusable (§7).
- **Giving `CveValidation` a policy**, or adding another resource with no
  policy authorizer. The login gate on `/gql` and `/mcp` is currently the only
  thing scoping those actions (§4).
- Opening any **currently-public read** to more data, or any
  **currently-POC-only** action to supporters.
- Adding another **build-gated authentication or authorization bypass**
  (as the mock login is, §5a), or making an existing one reachable in a
  `prod` build — whether by runtime flag or by compiling `dev/` into it.
- Removing a resource's strict `actor_present()` policy, or adding a private
  resource without one. The check is what turns an anonymous request into a
  refusal instead of an empty result (§4), and it is the only reason a
  console page can ask `Ash.can?` whether to render at all. Dropping it does
  not open a hole — the filter policies still scope the rows — but it does
  silently change a 401 into a blank page, and the model's claim that the two
  layers agree stops holding.
- Re-introducing a **route-level role gate** in the router. The model rests
  on there being exactly one place that decides (§4); a second one that can
  drift from the policies is the condition this section exists to catch.
- A report that **cannot be routed** to a §13 disposition — a `MODEL-GAP`;
  add the property to §8/§9 rather than making an ad-hoc call.

---

## 13. Triage dispositions

| Disposition | Meaning | Licensed by |
| --- | --- | --- |
| `VALID` | Violates a §8 property via an in-scope §7 adversary and §6 input. | §8, §6, §7 |
| `VALID-HARDENING` | No §8 property broken, but a §11 misuse is easy enough to warrant hardening (e.g. a `repo_url` public-host allowlist on top of the https + public-address checks). Fixed at maintainer discretion. | §11 |
| `OUT-OF-MODEL: trusted-input` | Requires control of an input the model marks trusted at that privilege (e.g. `repo_url`/`cve_json`/`cna_override` from below POC/assignee; catalog-sync URLs). | §6 |
| `OUT-OF-MODEL: adversary-not-in-scope` | Requires POC privilege, DB/host access, TLS break, or control of MITRE/GitHub/SMTP. | §7 |
| `OUT-OF-MODEL: unsupported-component` | Lands in the `/dev/*` tooling, or in the mock login (`/auth/user/mock/*`). | §3 |
| `OUT-OF-MODEL: non-default-build` | Only manifests in a release built from a non-`prod` `MIX_ENV` (which ships `dev/`), or with `TEST_DEPLOYMENT` misconfigured. | §5a |
| `OUT-OF-MODEL: report-upstream` | Lands in `exgit`/`mdex`/`cvelint`/`saxy`/`req` internals; Varsel ships the fix by bumping the dep. | §6b |
| `BY-DESIGN: property-disclaimed` | Concerns a §9 disclaimed property (rate limiting, `repo_url` egress to any public host within privilege, availability). | §9 |
| `KNOWN-NON-FINDING` | Matches a §11a recurring false positive. | §11a |
| `MODEL-GAP` | Routes to none of the above; triggers a §12 revision. | §12 |

**Precedence, where two rows both seem to fit:**

1. An exact §11a match wins — `KNOWN-NON-FINDING`.
2. Dev-only code — the `/dev/*` tooling and the mock login — routes two ways.
   If the report turns on that code being **present in a production build**,
   it is `non-default-build`, whatever the code then does. If it turns on how
   that code behaves where it does belong, it is `unsupported-component`.
3. A `repo_url` report turns on how the host **resolves**, never on how the
   name looks. Resolves privately → `KNOWN-NON-FINDING`, the check already
   rejects it, at save time and again when the clone connects. Resolves
   publicly → `BY-DESIGN`, any public host is allowed on purpose. A report
   that gets a clone to actually reach a private address — by rebinding or
   otherwise — is `VALID` against property 12.
4. Otherwise take the first matching row, reading the table top to bottom.

**Escalate rather than close when a claim rests on somebody else.** One claim
here holds only while something outside this codebase does: that a login
provider keeps a subject stable and non-reusable (§7). A report arguing that
no longer holds is **escalated to the maintainers, not closed against the
reporter** — record the disposition for tracking, but answer the reporter as
an open question. Everything else in §13 closes on its own authority.

---

## 14. Planned follow-ups

Hardening accepted as future work. Implementing any of these promotes a §9
disclaimer toward a §8 property, and the model updates in the same change.

- **Application-level rate limiting.** No in-app request-rate limit exists;
  volumetric DoS (report submission, search, reads) is currently the
  operator's edge responsibility. Investigate in-app rate limiting so the
  app carries a baseline itself.
