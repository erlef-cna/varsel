%{
  title: "Review & Publication",
  description: "Triage, review, publishing, and user management, for the CNA's Points of Contact"
}
---

Points of Contact see every case. They hand reported cases to supporters,
and handle what [supporters](/guide/filing-a-case) cannot: review,
publication, CVE IDs beyond the next free one, and user management.

## Triage

Each report from [the form](/report), the API, or hex.pm opens a case at
once. It waits in the Submitted column of the [Cases](/cases) board, and
moves to the Triage column when you mark it under triage. The reporter and the
maintainers hex.pm named are on the case from the start. You and the
supporters on it can edit the case while you triage it. The reporter and the
maintainers comment and suggest.

Assign a supporter to the case to triage it, or triage it yourself. The
decisions are the same either way, and
[Filing a CVE](/guide/filing-a-case) lists them. A maintainer can also submit
their GitHub advisory in place of a report; see
[GitHub Advisories](/guide/github-advisories#cases-that-start-from-an-advisory).

![The case board with a reported case in the Submitted column](/images/guide/report-triage.png)

## Review

Cases arrive in review when a supporter considers them ready. A
supporter's request notifies the Points of Contact assigned to the case, so
assign yourself to a case you mean to review. On a case with none assigned
it notifies the Points of Contact who turned on **Unassigned review** in
[Notification settings](/settings/notifications), or every Point of Contact
while nobody has. Sending a case to review yourself notifies nobody. The
[Cases](/cases) board shows the whole pipeline.

![Cases board with a case in the draft column and one in review](/images/guide/case-board.png)

Send a case back with your findings in the case comments, or approve it. You
still edit an approved case and accept suggestions on it, so late detail
needs no reopen. [When Plans Change](/guide/filing-a-case#when-plans-change)
has the freeze rules.

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

Varsel also renders every published case again on a schedule: daily in the
first month after publication, weekly in the first year, and monthly after
that. A case whose current render differs from its published record, or
can no longer be published, shows in the **Out of date** tab of the
[Cases](/cases) archive. **Recheck all** runs the check again for every
published case, for example after a fix to Varsel.

Each row opens the diff to the published record. **Republish** there pushes
the current render to MITRE as an update, without reopening the case. The
case content stays the same, but the output can change in substance: a
fix to how Varsel derives versions can change the affected ranges. Read the
diff before you republish.

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
tell the person. Case access is granted from the case, as
[Filing a CVE](/guide/filing-a-case) describes. Removing someone from a case
is yours alone and sends nothing.

![The user management table with one account per role](/images/guide/user-management.png)
