%{
  title: "Maintainer Process",
  description: "How coordinated disclosure works for maintainers when the EEF CNA is involved"
}
---

This page explains how coordinated disclosure works when the EEF CNA is involved,
whether we reached out to you or you came to us with a report from a third party.

## 1. How We Work Together

You and the CNA each own one part of the disclosure:

- **You own the advisory and the fix.** You triage the report, write the patch,
  release it, and publish your GitHub Security Advisory.
- **The CNA owns the CVE record.** We assign the CVE ID and write the published
  record: description, severity, weakness classification, affected versions, and
  credits. We publish it to [CVE.org](https://www.cve.org/),
  [OSV.dev](https://osv.dev/), and [Hex.pm](https://hex.pm/).

The **EEF CNA GitHub App** connects the two. With the app installed on your
repository, the CNA reads your advisory, follows its discussion, and writes the
CVE ID and the record's metadata on it. You keep working on GitHub, and we
do not have to copy anything by hand. We strongly encourage you to install it.
[§5](#5-the-github-integration) lists what the app does.

## 2. Enable Private Vulnerability Reporting

We strongly recommend
[GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
It lets reporters and the CNA report a vulnerability to you privately. It keeps
all communication, patches, and timelines in one private advisory.

In your GitHub repository, go to the *Security and Quality* page and click
*"Enable vulnerability reporting"*. This opens the repository settings. Click
*"Enable"* in the *Private vulnerability reporting* section.

![Security and Quality page with Enable vulnerability reporting button highlighted](/images/maintainer-process/enable-private-reporting-1.png)

![Repository settings with Enable button in Private vulnerability reporting section](/images/maintainer-process/enable-private-reporting-2.png)

## 3. Getting Started

### 3.1 You Have a GitHub Security Advisory

This is the preferred way to bring a vulnerability to the CNA. It applies when a
third party reported a vulnerability to you and the advisory is on your
repository.

:::steps
1. **Report the advisory on this site**

   Sign in with GitHub and open the [report form](/report){rel=nofollow}. Answer that there is
   an advisory and that you maintain the repository, then paste the advisory's
   URL.

2. **Install the EEF CNA GitHub App**

   When the app is not yet installed on the repository, the form asks whether you
   can install it, and links to it. Installing an app takes owner rights on the
   account that holds the repository. It takes admin rights on the repository
   when the owner lets admins install apps. After the install, click *Check
   again* and submit.

   ![The report form asking whether you can install the EEF CNA GitHub App on the advisory's repository](/images/maintainer-process/report-advisory.png)

3. **Follow the case**

   The form opens a case for the advisory on this site, and you are on it from
   the start. The CNA acknowledges it within **two business days**. From here,
   [§4](#4-the-disclosure-process) describes the rest.
:::

If you cannot install a GitHub App on the repository, answer *No*. The form then
asks you to add our Points of Contact to the advisory as collaborators, and to
send us the advisory's URL with a short report. Everything still works, but each
sync step becomes a manual step on our side.

![GitHub advisory collaborators section](/images/maintainer-process/collaborators.png)

### 3.2 The CNA Contacts You

When we receive a vulnerability report about your project, we contact you
directly. On GitHub, we send you a private vulnerability report, which opens a
draft advisory on your repository. Otherwise, we email you.

You also get an email that invites you to the case on this site. It tells you
what to expect and when we need an answer. You do not need a fix to reply.

Install the EEF CNA GitHub App on the repository, so the case and the advisory
stay in sync (see [§5](#5-the-github-integration)). Your CNA contact
sends you the link.

### 3.3 Without GitHub

If your project is not hosted on GitHub, [report the vulnerability on this
site](/report){rel=nofollow} without an advisory. The form opens a case, and you are on it
from the start. Coordinate in the case's comments: they stay with the CVE
record, and everyone on the case sees them.

Use email only when the case does not work for you. Write to
**cna@erlef.org**. Encrypted communication is also supported. See the
[Contact page](/contact) for our GPG key and fingerprint.

## 4. The Disclosure Process

Once initial contact is established, the typical workflow is as follows:

:::steps
1. **Triage**

   Review the advisory or report. Confirm the issue is valid and assess its severity.

2. **Add Reporters as Collaborators**

   Invite the original reporters to your private advisory. They can clarify details
   and verify that your patch addresses the issue.

   ![GitHub advisory collaborators section](/images/maintainer-process/collaborators.png)

3. **Write the Advisory**

   Describe the vulnerability in enough detail for the CNA to understand it.
   We draft the full advisory text for the CVE. You can take it over to your
   advisory, or write your own. Credit everyone who found, reported, or
   helped fix the vulnerability, with their GitHub login. You know these
   people best, and we take the credits over into the CVE record. Leave the
   severity and the weaknesses to us.

   For the CVE ID, choose *"Request CVE ID later"* when you create the
   advisory. Do **not** request a CVE ID from GitHub. We set the CVE ID on the
   advisory through the integration.

   ![Advisory creation form with Request CVE ID later option selected](/images/maintainer-process/cve-later.png)

   Without the app, enter the ID we give you yourself: go to *Edit* → *CVE
   identifier* → *I have an existing CVE ID*.

   ![Advisory edit form with I have an existing CVE ID option and input field](/images/maintainer-process/cve-input.png)

4. **Create a Private Fork**

   Use GitHub's *"Start a temporary private fork"* button on the advisory page.
   All patch development should happen in this private fork, not on your public
   repository. Without GitHub, post the patch as a diff in a case comment.

   CI does not run on the private fork, so run your tests locally. When you
   merge, GitHub merges all open PRs of the fork at once, and only one of them
   may target `main`. GitHub's guide to
   [collaborating in a temporary private fork](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/collaborating-in-a-temporary-private-fork-to-resolve-a-repository-security-vulnerability)
   has the details.

   ![Advisory page with Start a temporary private fork button](/images/maintainer-process/temporary-fork-start.png)

   ![Temporary private fork repository info](/images/maintainer-process/temporary-fork-repo-info.png)

5. **Develop the Patch**

   Push your fix to the private fork and open a Pull Request there. Do not push
   security-related changes to main or any public branch. Include the GHSA ID and
   CVE ID in your commit message.

   ![Terminal showing patch commit to private fork](/images/maintainer-process/patch-console.png)

   ![Pull request on temporary private fork](/images/maintainer-process/temporary-fork-pr.png)

6. **Review & Test**

   Reporters test the patch and provide feedback. Iterate privately until everyone
   is satisfied with the fix. In parallel, the CNA writes the CVE record: the
   [CWE](https://cwe.mitre.org/) (weakness type),
   [CVSS](https://www.first.org/cvss/) (severity score), affected versions,
   credits, and the CVE description. With the app installed, we set the
   metadata on your advisory.

7. **Coordinate Release Date**

   Agree on a publication date with the CNA. We appreciate a heads-up so we can
   be ready to publish the CVE promptly. Use the advisory's comments to
   coordinate. With the app installed, they also reach the case. Comments stay
   private even after the advisory is published.

8. **Merge & Release**

   Merge the private PR, and publish a new release to Hex.pm (or your relevant
   registry). Do this only on the agreed date.

   ![Merging the private fork pull request](/images/maintainer-process/temporary-fork-merge.png)

9. **Publish the Advisory**

   Publish the GitHub Security Advisory. This makes the vulnerability details
   publicly visible.

   ![GitHub Security Advisory publish button](/images/maintainer-process/publish-advisory.png)

10. **CNA Publishes the CVE**

    Once the advisory is published, we will publish the CVE to
    [CVE.org](https://www.cve.org/), [OSV.dev](https://osv.dev/),
    and [Hex.pm](https://hex.pm/). `mix deps.get` then warns users when
    they install a package with a known vulnerability. In the near future,
    `rebar3 deps get` and `gleam deps download` will warn them too.

    ![CVE published on cna.erlef.org](/images/maintainer-process/advisory-cna.erlef.org.png)

    ![CVE published on cve.org](/images/maintainer-process/advisory-cve.org.png)

    ![CVE published on osv.dev](/images/maintainer-process/advisory-osv.dev.png)

    ![CVE published on hex.pm](/images/maintainer-process/advisory-hex.pm.png)

11. **Public Announcement**

    We encourage you to inform your users about the vulnerability and the fix through
    your community channels such as Slack, Discord, forums, or mailing lists. If the
    CVE has high severity or the package has wide adoption, the CNA may also publish
    its own announcements.
:::

## 5. The GitHub Integration

When your advisory is linked to the case and the EEF CNA GitHub App is
installed on the repository:

- **Comments sync.** The advisory's discussion shows on the case
  automatically. A comment on the case can be posted on the advisory as well.
- **The CNA keeps the metadata up to date.** We set the CVE ID, severity,
  weaknesses, and affected versions on your advisory through the integration.
- **The description is yours.** We draft a full advisory text for the CVE.
  You decide whether your advisory takes it over or keeps your own.

The case's **GitHub** tab shows the case and the advisory field by field.

![The GitHub tab of a case: the CVE record and the advisory field by field](/images/maintainer-process/case-github-tab.png)

![Case comments, with a comment synced from the advisory and the option to post on the advisory as well](/images/maintainer-process/case-advisory-comments.png)

Without the app, the CNA does these steps by hand.

## 6. Following the Case on This Site

The CVE record is drafted on this site. We give you access to the case by your
GitHub or Hex.pm handle, and you sign in with that account. No prior
registration is needed. You can comment, and you can propose corrections to any
field of the record.

Everything on an unpublished case is embargoed and visible only to the people
on it. The [Varsel Guide](/guide) has the rest of the detail.

![An invited maintainer's view of an in-progress case: the draft record, their own suggestions, and the discussion](/images/guide/maintainer-view.png)

## 7. Timelines & Embargo

:::warning
**Do not make anything public before the advisory is published.** This includes public Pull Requests, commits to main, public issues, blog posts, social media posts, or any other public communication referencing the vulnerability. **If information becomes public, our disclosure timeline immediately shifts to 24 hours or less**, regardless of whether a patch is ready.
:::

Key timeframes:

- **Maximum embargo:** 3 months from the date we first contact you.
- **Non-response:** If we do not receive a response within **14 days**, we may proceed with
  publishing the CVE unilaterally.
- **Active exploitation:** If we become aware that the vulnerability is being actively
  exploited in the wild, we will publish within **24 hours**, regardless of patch status.
- **Coordination period:** We aim to be as flexible as possible, but all timelines are
  bounded by our [Security Policy](/security-policy).

Please remain reachable throughout the process. We will always try to give you a
heads-up before we publish.

## 8. What Not to Do

The following actions break the embargo and can cause the CVE to be published
immediately, even if no patch is available:

- Opening a public Pull Request that references or fixes the vulnerability
- Merging a security fix to `main` or any public branch before the advisory is published
- Including the CVE ID or vulnerability details in a public commit message
- Discussing the issue in a public GitHub issue or discussion
- Announcing a "security release" before the advisory is ready
- Posting about the vulnerability on social media, a blog, or a mailing list

## 9. Feedback

Once you are through the process, we would love to hear your feedback on this document.
If anything took extra time to figure out or required clarification, we want to know so
we can make it clearer for future maintainers. You can reach us via the
[Contact](/contact) page, or send a Pull Request directly to
[this file on GitHub](https://github.com/erlef-cna/varsel/blob/main/priv/pages/maintainer-process.md).

## 10. Further Resources

- [Contact](/contact) — Reach out to the CNA
- [CVE Criteria](/cve-criteria) — What qualifies for a CVE
- [Varsel Guide](/guide) — Following and contributing to a case on this site
- [Security Policy](/security-policy) — Full disclosure policy & timelines
- [EEF Security WG Guide](https://security.erlef.org/security_vulnerability_disclosure/) — Vulnerability handling best practices
