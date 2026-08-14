%{
  title: "Varsel Guide",
  description: "Working in Varsel, the application behind this site: filing cases, reviewing and publishing, and the tooling around it"
}
---

CNA processes run on [Varsel](https://github.com/erlef-cna/varsel), the
application this site runs on: report intake, case drafting, review,
publication to MITRE, and the derived OSV feeds.

Sign in with your GitHub or Hex.pm account. Registration is open, but a
fresh account holds no role; what you can do is decided by the role a CNA
Point of Contact gives you and by the cases you are on.

## Who Does What

- **Supporters** ([coordinators](/coordinator-process)) do the case work:
  open a case, write the record, bring the maintainer in, take a CVE ID, and
  hand the finished case to review, accepting or declining suggestions from
  collaborators along the way. Publishing is not theirs; a Point of Contact
  signs off.
- **Points of Contact** run the CNA: they triage inbound reports, review and
  publish cases, and manage roles and case access. They see every case.
- **Everyone else**, maintainers and reporters invited to a case, needs no
  role at all: they read the draft, comment, and suggest changes. The
  [Maintainer Process](/maintainer-process) explains what to expect.

## The Pages

- [Filing a CVE](/guide/filing-a-case) — the whole path from report to
  published record. Start here.
- [Review & Publication](/guide/review-and-publication) — triage, review,
  publishing, and user management, for Points of Contact.
- [Affected Versions](/guide/affected-versions) — what version facts to
  enter and how the published ranges are derived from them.
- [Record Conventions](/guide/record-conventions) — house style for
  descriptions, CVSS, CWE/CAPEC, credits, and references.
- [AI Tooling](/guide/ai-tooling) — the MCP server and the Claude Code
  skills that do the legwork.

Everything here is also reachable over GraphQL and MCP; see
[API Access](/api-access).
