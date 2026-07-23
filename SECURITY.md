<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

[![OpenSSF Vulnerability Disclosure](https://img.shields.io/badge/OpenSSF-Vulnerability_Disclosure-green)][openssf-cvd-finders-guide]
[![GitHub Report](https://img.shields.io/badge/GitHub-Security_Advisories-blue)][github-private-vulnerability-reporting]
[![Email Report](https://img.shields.io/badge/Email-cna%40erlef.org-blue)][email]

We take the security of this software seriously and are committed to ensuring
that any vulnerabilities are addressed promptly and effectively.

This repository follows the OpenSSF
[Vulnerability Disclosure guide][openssf-cvd-guide].
You can learn more about it in the [Finders Guide][openssf-cvd-finders-guide].

## Scope

Varsel is the CVE case-management service operated by the EEF CNA: it lets
authenticated points-of-contact triage vulnerability reports, build CVE
records and publish them to MITRE, and it serves the resulting public CVE,
OSV, CWE and CAPEC data read-only. [`THREAT_MODEL.md`](THREAT_MODEL.md) is the
detailed model — the trust boundaries, the roles, and the properties the
project does and does not defend; consult it (and cite the relevant section)
when deciding whether a finding is in scope.

**In scope** — reports that break a security property the project claims,
reachable by an attacker the model includes:

- Authentication or authorization bypass — reading or modifying data across
  the anonymous / authenticated-user / supporter / POC role boundaries (e.g.
  an anonymous client reading unpublished records, a supporter reaching a case
  they are not assigned to, any non-POC reaching publish authority).
- Leaking another user's personal data (email, GitHub identity, role) or a
  case's embargoed content.
- Exposure of secrets or credentials (API keys, tokens, OAuth or signing
  secrets).
- Stored or reflected XSS, CSRF, or clickjacking on the web surface.
- OAuth 2.1 flaws such as scope confusion between the MCP and GraphQL
  surfaces.

**Out of scope** — see `THREAT_MODEL.md` §3 and §9 for the reasoning:

- Anything requiring an already-privileged **POC** account, or database, host,
  TLS-intercept, or MITRE/GitHub/SMTP-provider access.
- The `/dev/*` dashboards (mount only under a development compile flag, never
  in production) and any instance left misconfigured
  (`TEST_DEPLOYMENT` not set to `false`, `dev_routes` compiled into a release).
- Denial of service by request volume or oversized payloads — application-level
  rate limiting and payload caps are the operator's edge responsibility.
- Outbound requests to a repository URL set on a case — that egress is a
  bounded POC/assigned-collaborator capability, not an anonymous SSRF, unless
  you can trigger it below that privilege.
- Bugs inside bundled third-party tools (`exgit`, `mdex`, `saxy`, `cvelint`),
  which we address by updating the dependency; report those upstream too.

If you are unsure whether something is in scope, report it anyway — we would
rather triage a borderline report than miss a real issue.

## Reporting Security Issues

If you believe you have found a security vulnerability in this repository,
please report it via [GitHub Security Vulnerability Reporting][github-private-vulnerability-reporting]
at `github.com/erlef-cna/varsel/security/advisories/new`
or via email to [`cna@erlef.org`][email] if that is more suitable for you.

**Please do not report vulnerabilities through public channels** such as GitHub
issues, discussions, or pull requests, to avoid exposing the details of the
issue before it has been properly addressed.

We don't implement a bug bounty program or bounty rewards, but will work with
you to ensure that your findings get the appropriate handling.

When reporting a vulnerability, please include as much detail as possible to
help us triage and resolve the issue efficiently. Information that will be
specially helpful includes:

- The type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the issue
- The location of the affected source code (e.g., tag, branch, commit, or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if available)
- The potential impact, including how the issue might be exploited by an attacker

Our vulnerability management team will respond within 3 working days of your
report. If the issue is confirmed as a vulnerability, we will open a Security
Advisory. This project follows a 90-day disclosure timeline.

If you have any questions about reporting security issues, please contact our
vulnerability management team at [`cna@erlef.org`][email].

[openssf-cvd-guide]: https://github.com/ossf/oss-vulnerability-guide/tree/main
[openssf-cvd-finders-guide]: https://github.com/ossf/oss-vulnerability-guide/blob/main/finder-guide.md
[github-private-vulnerability-reporting]: https://github.com/erlef-cna/varsel/security/advisories/new
[email]: mailto:cna@erlef.org