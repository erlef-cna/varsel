%{
  title: "Filing a CVE",
  description: "The whole path from vulnerability report to published CVE record, as a supporter works it"
}
---

This page is a supporter's path through a case, from a reported
vulnerability to a record in review. The [AI tooling](/guide/ai-tooling)
drafts most of the record as suggestions, and you review and decide.

:::steps
1. **Take on the case**

   A Point of Contact assigns you to a reported case while it waits in the
   Submitted column of [Cases](/cases){rel=nofollow}. Nothing about it is visible to anyone
   but the people on the case and the Points of Contact. Mark it *Under
   triage* while you work on it, hold it against the
   [CVE criteria](/cve-criteria), and decide on the case page:

   - **Accept** it, and it opens for filing as a draft.
   - **Reject** it with a reason. Its open invites are withdrawn.
   - **Merge** it into a case for the same finding. That case cites the
     report and takes over its people. You need to be on both cases.
   - **Split** off a new case for each further finding the report holds.

   A reporter may withdraw until you accept, and follows the outcome on the
   case.

   You can also open a case yourself under [Cases](/cases){rel=nofollow}, for a finding of
   your own or
   [from a GitHub advisory](/guide/github-advisories#cases-that-start-from-an-advisory).
   You are on it automatically.

2. **Take a CVE ID**

   Once the case is accepted, take the next free CVE ID on it.

   Is the vulnerability in code the package vendors from a project outside
   the CNA's [scope](/scope), such as a C library? Then the CNA responsible
   for that project assigns the CVE. Take no ID from the pool: a Point of
   Contact links the
   [upstream CVE](/guide/review-and-publication#upstream-cves) to the case.

3. **Write the record**

   Fill in the summary, the CVSS vector, the CWE/CAPEC classification,
   references, and credits. [Record Conventions](/guide/record-conventions)
   is the house style.

   Every change is either a direct edit or a suggestion, the same split as
   editing and suggesting in a shared document. Edit when you are sure,
   suggest when you want someone to look at it. Suggestions from others land
   on the case for you to accept or decline, and declining records why.

   ![Case workspace: the draft record, two open suggestions, and the activity feed](/images/guide/case-workspace.png)

4. **Enter the affected versions**

   Add the affected package (the `otp` / `elixir` / `gleam` presets prefill
   vendor, product, repository, and channels) and record two facts: the
   commit that introduced the vulnerability and the commit or commits that
   fixed it. Everything version-shaped in the published record is derived
   from them. [Affected Versions](/guide/affected-versions) covers the facts,
   the derivation, and the odd cases.

   ![The affected package with its channels and the derived version ranges](/images/guide/affected-packages.png)

5. **Bring people in**

   Grant the maintainer (and the reporter, if there is one) access by their
   GitHub or Hex.pm handle. Someone without an account gets an invite that
   becomes access on their first sign-in. Assigning someone notifies them
   in-app and by email, per their [notification
   settings](/settings/notifications){rel=nofollow}.

   An invited person gets one email with a sign-in link, at the primary
   address Hex.pm holds for them or the public address on their GitHub
   profile. When the provider lists no address, enter one you found at a
   trusted source, such as the author email on their commits in the affected
   repository. When you find no trusted address, tick *Send no email* and
   reach the person another way. The people panel shows what became of each
   invite email.

   Mark someone who maintains an affected package as a *Maintainer*: their
   invite email asks them to respond, says no fix is needed to start, and
   says we may publish without one after 14 days of silence, as the
   [maintainer process](/maintainer-process) states. Everyone else gets a
   plain invite. Hex.pm reports mark the package's maintainers for you.

   When the repository takes private vulnerability reports, also report the
   case to its maintainers from the **GitHub** tab; see
   [GitHub Advisories](/guide/github-advisories#reporting-to-the-maintainers).

   Notification emails never carry case details, only a link. Keep anything
   time-sensitive on the advisory thread, and use case comments for what
   should stay on record with the case. Type `@` in a comment to mention
   someone on the case.

6. **Verify**

   Clear the **Publication** tab and cross-check the rendered record, as
   [Verifying Before Review](/guide/record-conventions#verifying-before-review)
   lists. On a case linked to an advisory, the **GitHub** tab sets the two
   against each other field by field.

7. **Request review**

   Request review as soon as the record is complete. Do not wait for the
   patch or the release: an early request gives the Points of Contact time to
   review. [Review & Publication](/guide/review-and-publication#review)
   covers who is notified and what happens next. A Point of Contact publishes
   once the advisory is public.
:::

## When Plans Change

A case is editable while it is in draft or review. Approval freezes it for
everyone but a Point of Contact; publishing freezes it for everyone.

- **The published record needs a change?** Reopen the case, edit, publish
  again; the second publish reaches MITRE as an update. Fixes and
  improvements both qualify.
- **Not becoming a CVE after all?** A Point of Contact closes the case with
  a reason. An already-assigned CVE ID goes back to the pool, or the Point
  of Contact rejects it at MITRE. That is
  [their call](/guide/review-and-publication#closing-and-cve-ids).
