%{
  title: "Review & Publication",
  description: "Triage, review, publishing, and user management, for the CNA's Points of Contact"
}
---

Points of Contact see every case and handle what
[supporters](/guide/filing-a-case) cannot: triage, review, publication, and
user management.

## Triage

Reports from [the form](/report), the API, and hex.pm queue under
[Reports](/reports). Hold each against the
[CVE criteria](/cve-criteria): accepting opens a case linked to the report,
rejecting records why. Reporters follow the outcome on the same page.

![The report triage queue with a submitted report awaiting a decision](/images/guide/report-triage.png)

## Review

Cases arrive in review when a supporter considers them ready; the
[Cases](/cases) board shows the whole pipeline.

![Cases board with a case in the draft lane and one in review](/images/guide/case-board.png)

Send a case back with your findings in the case comments, or approve it,
which freezes the content for everyone but a Point of Contact. A Point of
Contact still edits an approved case and accepts suggestions on it, so late
detail needs no reopen. Publishing freezes the content for everyone.

Approval is judgement, not a second checklist: the record makes sense, the
[conventions](/guide/record-conventions) were followed, the CVSS holds, the
derived ranges match the advisory. What the CNA publishes is the CNA's
decision; see the
[governance policy](https://github.com/erlef-cna/.github/blob/main/GOVERNANCE.md).

## Publication

Publish when the coordinated disclosure allows: Varsel renders the record,
validates it, and pushes it to MITRE. The OSV record, the feeds, and the
hex.pm advisory data follow automatically.

Amending later means reopening the case, editing, and publishing again; the
next publish reaches MITRE as an update. Fixes and improvements both
qualify.

## Closing and CVE IDs

Closing a case records a reason and is terminal. A case that already holds a
CVE ID forces one more call, rejecting the ID at MITRE or explicitly parking
it, and the answer turns on whether the ID was ever communicated outside
the CNA.

Supporters take the next free ID of the year; everything else is yours:
assigning a specific reserved record, a withheld ID, or one out of sequence,
adopting an already-existing CVE record into a new case, and linking an
upstream CVE.

## Upstream CVEs

A package can vendor code from a project outside the CNA's [scope](/scope),
for example a C library. The CNA rules forbid the CNA to assign a CVE for a
vulnerability in that code: the CNA responsible for the vendored project
assigns it. Link that CVE ID to the case from **Assign CVE ID**
instead of taking one from the pool. The ID can still be RESERVED, so a case
can follow an embargo.

The case is written and reviewed as usual. Publishing adds the case's content
to the upstream CVE record as the CNA's ADP container, and sends nothing to
MITRE. The CVE page shows that enrichment, with the upstream CNA's title and
summary and a link to cve.org. The OSV record keeps the `EEF-` ID and names
the CVE as `upstream`. Validation checks the CVE schema only, so review the
[conventions](/guide/record-conventions) in full.

Publishing waits until the upstream CNA publishes the CVE: while the ID is
RESERVED at MITRE, the case shows a blocker. Varsel checks the upstream record
at MITRE on a schedule, so publish once the blocker is gone. Closing an
upstream case unlinks the ID. Another CNA owns it, so there is nothing to
reject.

## People

Roles are granted under [Users](/users): new coordinators get the
supporter role once they have signed in, and a change takes effect
immediately, open sessions included. No email goes out on a role change, so
tell the person. Case access works from the case by GitHub or Hex.pm handle
and reaches people without an account via invites; granting it notifies the
person in-app and by email, per their [notification
settings](/settings/notifications). That email is content-free, so still
tell them what changed on the advisory thread. Removing someone is yours alone and sends
nothing.

![The user management table with one account per role](/images/guide/user-management.png)
