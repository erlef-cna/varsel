%{
  title: "Filing a CVE",
  description: "The whole path from vulnerability report to published CVE record, as a supporter works it"
}
---

Vulnerabilities reach us as GitHub advisory invites, email, reports
submitted [on this site](/report), and findings of our own. This page is the
path from there to a published CVE.

:::steps
1. **Open the case**

   If the vulnerability warrants a CVE (check the
   [criteria](/cve-criteria)), open a case under [Cases](/cases). You are on
   it automatically, and nothing about it is visible to anyone but the
   people on the case and the Points of Contact. A vulnerability that
   reached you as a GitHub security advisory opens from the same place:
   paste the advisory's URL or GHSA id, and the case arrives filled in from
   it, with the advisory linked.

2. **Write the record**

   Fill in the summary, the CVSS vector, the CWE/CAPEC classification,
   references, and credits. [Record Conventions](/guide/record-conventions)
   is the house style, and the [AI tooling](/guide/ai-tooling) drafts most
   of this for you as suggestions.

   Every change is either a direct edit or a suggestion, the same split as
   editing and suggesting in a shared document. Edit when you are sure,
   suggest when you want someone to look at it. Suggestions from others land
   on the case for you to accept or decline, and declining records why.

   ![Case workspace: the draft record, two open suggestions, and the activity feed](/images/guide/case-workspace.png)

3. **Enter the affected versions**

   Add the affected package (the `otp` / `elixir` / `gleam` presets prefill
   vendor, product, repository, and channels) and record two facts: the
   commit that introduced the vulnerability and the commit or commits that
   fixed it. Everything version-shaped in the published record is derived
   from those facts and the repository, so verify them: full commit SHAs,
   never trusted from the advisory.

   After changing them, press **Derive the case**: derivation runs only on
   demand, and an out-of-date one shows up as *no affected versions*. If the
   derived ranges disagree with the advisory, a boundary commit is wrong.
   [Affected Versions](/guide/affected-versions) covers the details and the
   odd cases: unreleased hotfixes, missing repositories, prereleases.

   ![The affected package with its channels and the derived version ranges](/images/guide/affected-packages.png)

4. **Bring the maintainer in**

   Grant the maintainer (and the reporter, if there is one) access by their
   GitHub or Hex.pm handle. Someone without an account gets an invite that
   becomes access on their first sign-in. Assigning someone notifies them
   in-app and by email, per their [notification
   settings](/settings/notifications). An invited person gets one email with
   a sign-in link, at the primary address Hex.pm holds for them or the
   public address on their GitHub profile. When the provider lists no
   address, enter one you found at a trusted source, such as the author
   email on their commits in the affected repository. When you find no
   trusted address, tick *Send no email* and reach the person another way.
   The people panel shows what became of each invite email.
   Notification emails never carry case details, only a link, so the
   advisory thread is still where they hear what changed. The same holds for
   comments and proposals: keep anything time-sensitive on the advisory
   thread and use case comments for what should stay on record with the
   case. On a case linked to an advisory, a comment can be both: the comment
   form offers to post it on the advisory as well. It posts as you where
   your GitHub login may write there, and as the EEF CNA app naming you
   where it may not.

5. **Verify**

   Open the case's **Publication** tab and clear everything it flags:
   publish blockers are hard stops, and the built-in validation (CVE schema,
   cvelint, hex.pm package check) must pass. Then cross-check the rendered
   record on the **CVE** tab against the advisory one last time: ranges,
   credits, resolved `TODO`s.

   The **GitHub** tab does that cross-check for a GitHub security advisory.
   Link the advisory by its URL or its GHSA id, and the tab sets the case
   against it field by field: title, description, CVE ID, CVSS vector, CWEs,
   credits, and the derived ranges of each channel, spelled the way GitHub
   spells them. Pull a field when the advisory should win, or push it when
   the case should. A pull adds and replaces and never removes. A push
   writes to the advisory as you, so GitHub decides whether you may. Refresh
   reads the advisory again after it changed on GitHub. The linked advisory
   leads the published references as the vendor advisory, and no stored
   reference is needed for it. Unlink takes it out again. Linking, pulling
   and unlinking are edits and follow the same freeze as the case content:
   approval stops them for everyone but a Point of Contact. Advisories are
   read and written with your GitHub account, on repositories where the
   repository's owner installed the EEF CNA app and your account is an
   owner, collaborator or member. When your account cannot act on the
   repository, the tab says so and holds Refresh, Push and Report, and its
   owner needs to install the EEF CNA app. When no GitHub account is linked
   to yours, the tab holds them until you
   [link GitHub in account settings](/settings/account). The settings page
   then shows where the app can act for you and links to GitHub to change
   it. A Point of Contact without a linked GitHub account, or whose account
   cannot act on a repository with the app installed, or whose request
   GitHub refuses there, acts through the app instead, and GitHub shows the
   app as the author.

   Where the app is not installed, a Point of Contact does the request from
   their own terminal with the GitHub CLI, `gh`. Link, Refresh, Pull, Push
   and Report each offer to do it with gh, and show one command. Opening a
   case from an advisory offers the same command on the cases console. The
   command fetches the request from here, sends it to GitHub with `gh api` as
   your GitHub account, and posts GitHub's answer back. The tab then records the
   answer as you and updates. The command works once, for 15 minutes. The
   tab cannot ask GitHub whether you administer the repository, so for a
   report choose a draft advisory when you do and a private report when you
   do not.

   A case that has no advisory yet is reported from the same tab to the
   maintainers of one of its GitHub repositories, as a private vulnerability
   report in your name, with everything the case states and a description
   you write for them. The advisory GitHub opens for the report becomes the
   linked one. A repository that takes no private reports is flagged there,
   with the [maintainer process](/maintainer-process) to point its
   maintainers at. Where you administer the repository, GitHub takes no
   report from you and the case opens a draft advisory in your name instead.
   A report a Point of Contact makes through the app opens a draft advisory
   as the app.
   A linked advisory also lists who sees it on GitHub, its collaborators,
   its teams and the organization's owners, marks who is on the case, and
   gives the rest access with one click, as an assignment or an invite. The
   invite email goes to the address GitHub lists for the person, and an
   account without one is invited without an email: they already see the
   advisory on GitHub.

6. **Take a CVE ID and hand it to review**

   Take the next free CVE ID, then send the case to review. A Point of
   Contact sends it back with findings, or approves it and, once the
   advisory is public, [publishes](/guide/review-and-publication): Varsel
   pushes the record to MITRE, and the OSV feed and hex.pm advisories follow
   automatically.
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
  [their call](/guide/review-and-publication).
