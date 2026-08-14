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
which freezes the content until it is published or reopened.

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
and adopting an already-existing CVE record into a new case.

## People

Roles are granted under [Users](/users): new coordinators get the
supporter role once they have signed in, and a change takes effect
immediately, open sessions included. Case access works from the case by
GitHub or Hex.pm handle and reaches people without an account via invites;
removing someone is yours alone. No email goes out on any of it yet, so tell
the person.

![The user management table with one account per role](/images/guide/user-management.png)
