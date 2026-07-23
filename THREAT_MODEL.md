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
  against the model as it stood at that version. Written against `f9d95f5`.
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
  GraphQL and MCP, but those endpoints **require a login** (API key or OAuth
  token) — they are not an anonymous surface. (`README.md`, `router.ex`)

**Deployment context.** A public-facing web service behind TLS on Fly.io,
config entirely from environment variables/secrets (`README.md`,
`runtime.exs`). HTTPS termination, network-level rate limiting, and DDoS
protection are the platform's/operator's job, not the app's.

**Caller roles.** Unlike a library, there is no single "caller." Four roles:

- **Anonymous / public** — untrusted internet clients. See only published
  data.
- **Authenticated user (no role / `nil`)** — a logged-in GitHub user with
  no CNA role. Minimal rights: submit a vulnerability report, manage their
  own API keys.
- **Supporter** — a CNA collaborator scoped to the specific cases they are
  assigned to. Can read and edit content on those cases; cannot run
  lifecycle actions or publish.
- **POC (point of contact)** — privileged CNA operator. Full lifecycle
  authority, including publishing to MITRE and assigning roles.

Roles live in `Varsel.Accounts.User.Role` (`:poc | :supporter`, plus `nil`)
— see `user/role.ex`.

### Component-family table

| Family | Entry point | Touches outside process? | In model? |
| --- | --- | --- | --- |
| Anonymous read surface (CVE/OSV JSON, HTML, feeds) | `/cves`, `/osv`, `/`, `/feed.*` | DB reads | **Yes** |
| Authenticated API (GraphQL, MCP) — login-gated even for read tools | `/gql`, `/mcp` | DB reads/writes, workbench tools | **Yes** |
| Auth surface (GitHub OAuth login, OAuth 2.1 server, API keys, session) | `/auth`, `/oauth/*`, `/sign-in`, `/settings/tokens` | GitHub IdP, DB | **Yes** |
| CNA workbench (cases, reports, CVE lifecycle, user mgmt) — LiveView + GraphQL/MCP tools | `/cases`, `/reports`, `/users`, `/cves/manage`, GraphQL/MCP POC tools | DB, **MITRE API**, **git egress** | **Yes** |
| Render-time derivation (`exgit` git clone/fetch of package repos) | `Varsel.Cases.Derivation` | **Outbound git to `repo_url`** | **Yes — key boundary (§4)** |
| Catalog sync (CWE/CAPEC/OTP-versions) — Oban jobs | scheduled workers | Outbound HTTPS to fixed hosts | **Yes (trusted-source egress)** |
| `cvelint` subprocess (validates rendered CVE JSON) | `Varsel.CVE.Cvelint` | `System.cmd`, temp file | **Yes** |
| Dev dashboards (LiveDashboard, Oban Web, AshAdmin, Swoosh mailbox) | `/dev/*` | DB, mail | **No — §3 (compile-flag only)** |
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
- **The dev dashboards** (`/dev/dashboard`, `/dev/oban`, `/dev/admin`,
  `/dev/mailbox`). They mount only under the `:dev_routes` compile flag,
  never in a production release, and deliberately run a relaxed CSP.
  Findings against them are `OUT-OF-MODEL: unsupported-component`
  (`router.ex`).
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
  `role == :poc OR ActorAssignedToCase`). A finding here that assumes an
  *ordinary* authenticated user or anonymous caller controls `repo_url` is
  out of model. (`affected_package.ex`)
- **Report intake** — reachable by **any authenticated user**. `report_json`
  is fully attacker-controlled at that privilege; downstream sinks (email,
  triage UI) are the question.
- **Catalog sync / MITRE import** — the egress targets are compile-time
  constants (the CWE/CAPEC/OTP-versions URLs) or a single operator-configured
  endpoint (`MITRE_CVE_API_BASE_URL`); no actor picks where these requests go.
  A finding premised on an *actor controlling those URLs* is out of model.
- **CVE lifecycle writes** — POC-only. Not reachable below POC.

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
- **Writes to disk** — only the transient `cvelint` temp file (removed in an
  `after`); `exgit` and the catalog unzip are **in-memory**. (`cvelint.ex`,
  `weakness.ex`, `git_repo.ex`)

### 5a. Build-time and configuration variants

| Knob | Default | Effect on model |
| --- | --- | --- |
| `:dev_routes` (compile) | off in prod | Mounts the dev dashboards (§3). If ever compiled into a prod release, those tools are exposed and this model no longer holds. (`router.ex`) |
| `TEST_DEPLOYMENT` (runtime) | `true` | When true, serves a disallow-all `robots.txt`, `X-Robots-Tag: noindex`, and a warning banner. **Must be set `false` on the real production instance.** Not a security control — an indexing/labeling one. (`config.exs`, `runtime.exs`) |
| `MITRE_CVE_API_BASE_URL` | none (required) | Points the publish pipeline at a MITRE endpoint. Every configured endpoint (including MITRE's shared staging, `cveawg-test`) is a real remote system — the pipeline has no in-app dry-run or sandbox, so any publish leaves the machine (see §9, "false friend"). (`mitre_cve_api.ex`) |
| GraphiQL relaxed CSP | route-scoped | `/gql/playground` serves `'unsafe-inline'` + a jsdelivr allowlist so GraphiQL boots. The rest of the site is deny-by-default (`default-src 'none'`, `script-src 'self'`, nonce'd). The relaxation is confined to that one login-gated route. (`router.ex`, `config.exs`) |

No build knob silently voids a §7 auth property; the two that matter
(`:dev_routes` compiled into prod, `TEST_DEPLOYMENT` left true) are
operator-deployment errors, surfaced in §10.

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
| `Case.cna_override` | RFC 7396 merge patch on rendered container | POC / assigned supporter | Applied as last render step; can override any rendered field (`case.ex`) |
| GitHub OAuth | `user_info` (sub, preferred_username, name, email) | IdP-supplied, verified by GitHub | Stored as `github_id/handle/name/email`; `handle` later in a client-side `img`/link |
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
| CVE JSON / OSV JSON / feeds | Machine consumers, cross-origin | N/A (data) — CORP dropped deliberately for these (`public_resource.ex`) | — |
| POC notification email | Plain-text mail | Yes — `text_body`, fixed headers, and **content-free**: it carries only a link to the authenticated triage console, no report payload or reporter identity, since email is unencrypted in transit/at rest (`emails.ex`) | — |
| Published CNA container → MITRE API | MITRE (trusted) | JSON body; MITRE is trusted sink | — |

Every markdown/HTML render sink now sanitizes (ammonia allow-list) before
`raw/1`, so injected script/handlers are stripped at the source. The app-wide
**strict CSP** (`default-src 'none'`, `script-src 'self'` with per-request
nonce, **no `unsafe-inline`/`unsafe-eval`**) is a second, independent layer:
even a sanitizer bypass would need an inline `<script>`/event handler the
browser refuses. (`config.exs`) The CSP relaxation does
**not** apply to the main site — only to `/gql/playground`, which is
login-gated and serves no user-authored content (§5a).

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
- **Anyone who controls the MITRE API, GitHub IdP, or the SMTP relay.** These
  are trusted integration partners; compromising them is out of layer.
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
restated as Varsel claims).

1. **Role-scoped authorization on every resource.**
   Every action is policy-gated; the role→action matrix in §2 holds. No
   exposed action grants callers `authorize?: false` (verified: that flag
   appears only in internal changes/jobs, never in a caller-reachable
   contract).
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

3. **Field-level PII redaction on `User`.**
   A non-POC who reaches a `User` row through a permitted relationship sees
   only `:name`; `email`, `github_id`, `github_handle`, `role` are POC-or-self.
   - *Violation symptom:* a non-POC reads another user's email/handle/role.
   - *Severity:* `high`.
   - (`user.ex`)

4. **Case content is confined to assigned collaborators.**
   Reads and edits of a case and all its child rows require POC or a
   `CaseAssignment` for that case; supporters cannot self-assign (assignment
   create/destroy is POC-only).
   - *Violation symptom:* a supporter reads or edits a case they are not
     assigned to.
   - *Severity:* `high` (unpublished advisory content is embargoed).
   - (`case.ex`, `case_assignment.ex`)

5. **OAuth scope separation between surfaces.**
   An OAuth 2.1 access token carries a scope (`mcp` or `gql`); a token
   without the required scope for a surface gets `403 insufficient_scope`.
   API keys and session JWTs (first-party credentials) are exempt by design.
   - *Violation symptom:* a `gql`-scoped token invokes an MCP tool, or vice
     versa.
   - *Severity:* `high`.
   - (`oauth_bearer_auth.ex`)

6. **API keys and tokens stored hashed / redacted.**
   Only a SHA-256 hash of an API key is persisted; the plaintext is shown
   once. Token `jti` and key hashes are `sensitive?`; error redaction is on
   (`redact_sensitive_values_in_errors?: true`).
   - *Violation symptom:* a recoverable key/secret appears in the DB, a log,
     or an error response.
   - *Severity:* `high`.
   - (`api_key.ex`, `token.ex`, `config.exs`)

7. **Stored-content rendering is sanitized before display.**
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

8. **Report intake is size-bounded.**
   `report_json` (the one unbounded authenticated write) is capped at a
   configurable serialized size (default 256 KiB); an oversized payload is
   rejected before persistence.
   - *Violation symptom:* an authenticated user stores an arbitrarily large
     payload.
   - *Severity:* `moderate` (storage/DoS).
   - (`report_json_size.ex`)

9. **CSRF / clickjacking / cross-origin hardening on the browser surface.**
   `protect_from_forgery` on browser pipelines; `x-frame-options: DENY` +
   `frame-ancestors 'none'`; `permissions-policy`, COOP `same-origin`, CORP
   `same-site` (dropped only for the public JSON/feed data by design).
   - *Violation symptom:* a cross-site POST is accepted, the app is framed,
     or a private response is fetched cross-origin.
   - *Severity:* `high`.
   - (`router.ex`, `security_headers.ex`, `public_resource.ex`)

**Resource bound (the one quantified DoS line we can state):** guardrails are
the git-derivation timeout (10 min), cache TTL (900 s), and 250k commit-count
cap, the Oban `Lifeline` rescue (30 min) for orphaned jobs, the `report_json`
size cap (default
256 KiB, property 8), and `max_length` caps on every free-text/markdown field
(title 500; `*_md`/comment/notes 20–50 KB; report body 200 KB) that bound the
parser input. There is still **no application-level request-rate limit** — so
submission *rate* and read-endpoint volume are not bounded in-app, and
"bounded resource use" is **not** a general claim (§9).

---

## 9. Security properties the project does *not* provide

- **No rate limiting or request-volume DoS defense at the application layer.**
  Report submission, search queries (full-text `tsquery`), and read endpoints
  are not rate-limited in-app; the operator/platform must provide it. Payload
  *size* is capped (property 8), but an authenticated user can still submit
  arbitrarily many capped `report_json` payloads. Accepted as the operator's
  edge responsibility for now; in-app rate limiting is planned (§14).
- **No allowlist on which public host `repo_url` may name.** `repo_url` is
  constrained to `https://` (rejecting exgit's `file://` local-file read and
  plaintext `http://`) and to a host that resolves to a public address —
  loopback, RFC 1918, link-local, unique-local, CGNAT and other special-use
  ranges are rejected, so a case editor cannot aim egress at an internal
  service (`repo_url_https.ex`, `private_address.ex`). Beyond that the host is
  unrestricted on purpose, since a public self-hosted forge is a supported
  source: derivation will clone any public https host a POC/assignee names.
- **No availability/uptime guarantee.**
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
2. **Never compile a release with `:dev_routes` enabled** — it would expose
   LiveDashboard/Oban/AshAdmin/mailbox with a relaxed CSP.
3. **Terminate TLS at the edge and forward the scheme** — the app forces
   HTTPS + HSTS itself (`force_ssl`), but relies on the proxy setting a
   truthful `x-forwarded-proto`; a proxy that lets a client spoof it to
   `https` would defeat the redirect.
4. **Provide request rate limiting and payload-size limits at the edge** —
   the app does not (report intake, search, reads).
5. **Keep the MITRE/GitHub/SMTP credentials and `CLOAK_KEY` /
   `*_SIGNING_SECRET` out of source and rotate on schedule** — all are
   environment secrets.
6. **Grant the POC role deliberately.** POC is full publish authority; the
   first-ever GitHub login auto-becomes POC (bootstrap), so control who logs
   in first. (`user.ex`)
7. **Treat `repo_url` on cases as a trusted-egress control:** only assign
   supporters to cases you trust to set outbound clone targets; if egress
   filtering matters, enforce it at the network layer.
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

---

## 12. Conditions that would change this model

- Adding a **plugin/extension/webhook** surface, or any dynamic code/tool
  loading (today the MCP/GraphQL tool list is fixed).
- Making Varsel **multi-tenant** or self-hostable by third-party CNAs.
- Accepting a **new attacker-controllable input** that reaches a subprocess,
  a network egress, or an unsafe render sink — especially any new consumer of
  `report_json` beyond email/triage, or any new `unsafe: true` render path.
- Implementing any **§14 planned follow-up** (`repo_url` commit-count limit,
  private-network egress block, or application-level rate limiting) — each
  promotes a §9 disclaimer toward a §8 property.
- Opening any **currently-public read** to more data, or any
  **currently-POC-only** action to supporters.
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
| `OUT-OF-MODEL: unsupported-component` | Lands in the `/dev/*` dashboards. | §3 |
| `OUT-OF-MODEL: non-default-build` | Only manifests with `:dev_routes` compiled in or `TEST_DEPLOYMENT` misconfigured. | §5a |
| `OUT-OF-MODEL: report-upstream` | Lands in `exgit`/`mdex`/`cvelint`/`saxy`/`req` internals; Varsel ships the fix by bumping the dep. | §6b |
| `BY-DESIGN: property-disclaimed` | Concerns a §9 disclaimed property (rate limiting, `repo_url` egress to any public host within privilege, availability). | §9 |
| `KNOWN-NON-FINDING` | Matches a §11a recurring false positive. | §11a |
| `MODEL-GAP` | Routes to none of the above; triggers a §12 revision. | §12 |

---

## 14. Planned follow-ups

Hardening accepted as future work. Implementing any of these promotes a §9
disclaimer toward a §8 property, and the model updates in the same change.

- **Application-level rate limiting.** No in-app request-rate limit exists;
  volumetric DoS (report submission, search, reads) is currently the
  operator's edge responsibility. Investigate in-app rate limiting so the
  app carries a baseline itself.
