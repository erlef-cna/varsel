%{
  title: "Maintainer Process",
  description: "How coordinated disclosure works for maintainers when the EEF CNA is involved"
}
---

This page explains how coordinated disclosure works when the EEF CNA is involved,
whether we reached out to you or you came to us with a report from a third party.

## 1. How You May Be Contacted

### 1.1 The CNA Contacts You

If we have received a vulnerability report concerning your project, we will reach out to
you directly. You can expect a personal email from one of our Points of Contact, or an
invitation to a **GitHub Security Advisory** on your repository.

Our initial message will include:

- A summary of the reported vulnerability
- The CVE ID we have reserved (or a note that we will assign one)
- A request to confirm your preferred coordination channel (GitHub Advisory or email)

### 1.2 You Contact the CNA

If you have received a vulnerability report from a third party and need a CVE number,
please reach out to us via our [Contact](/contact) page. We will acknowledge your report
within **two business days** and guide you through the rest of the process.

## 2. Preferred Channel: GitHub Private Vulnerability Reporting

We strongly recommend using [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for coordinating disclosure. It keeps all communication, patches, and timelines in one
place, and makes it easy to collaborate privately.

:::steps
1. **Enable Private Vulnerability Reporting**

   In your GitHub repository, go to the *Security and Quality* page and click
   *"Enable vulnerability reporting"*. This will navigate you to the repository
   settings — click *"Enable"* in the *Private vulnerability reporting* section.

   ![Security and Quality page with Enable vulnerability reporting button highlighted](/images/maintainer-process/enable-private-reporting-1.png)

   ![Repository settings with Enable button in Private vulnerability reporting section](/images/maintainer-process/enable-private-reporting-2.png)

2. **Invite the CNA as Collaborators**

   Add our Points of Contact to the private advisory so we can assist with triage, assign the CVE ID, and coordinate publication.

   - `@IngelaAndin` — Ingela Andin, OTP Core Contributor
   - `@maennchen` — Jonatan Männchen, CISO, EEF
   - `@voltone` — Bram Verburg, Security WG Chair

   ![GitHub advisory collaborators section](/images/maintainer-process/collaborators.png)

3. **Set the CVE ID Field**

   When creating the advisory, choose *"Request CVE ID later"*. Once we
   provide the CVE ID, edit the advisory and select *"I have an existing CVE ID"*.

   ![Advisory creation form with Request CVE ID later option selected](/images/maintainer-process/cve-later.png)

   ![Advisory edit form with I have an existing CVE ID option and input field](/images/maintainer-process/cve-input.png)
:::

## 3. Email Alternative

If your project is not hosted on GitHub, or you prefer email, you can coordinate
everything through **cna@erlef.org**. Encrypted communication is also supported; see
the [Contact page](/contact) for our GPG key and fingerprint.

## 4. The Disclosure Process

Once initial contact is established, the typical workflow is as follows:

:::steps
1. **Triage**

   Review the advisory or report. Confirm the issue is valid and assess its severity.

2. **Add Reporters as Collaborators**

   Invite the original reporters to your private advisory. They can clarify details
   and verify that your patch addresses the issue.

   ![GitHub advisory collaborators section](/images/maintainer-process/collaborators.png)

3. **Set the CVE ID**

   We will provide you with a CVE ID. In the advisory, go to
   *Edit* → *CVE identifier* → *I have an existing CVE ID*
   and enter the ID we give you. Do **not** request a CVE ID from GitHub.

   ![Advisory edit form with I have an existing CVE ID option and input field](/images/maintainer-process/cve-input.png)

4. **Create a Private Fork**

   Use GitHub's *"Start a temporary private fork"* button on the advisory page.
   All patch development should happen in this private fork, not on your public
   repository. If you are coordinating via email, you can also send the patch as an
   attachment or inline diff instead.

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
   is satisfied with the fix. In parallel, the CNA will fill in the advisory details:
   [CWE](https://cwe.mitre.org/) (weakness type),
   [CVSS](https://www.first.org/cvss/) (severity score), credits, and
   the public description.

7. **Coordinate Release Date**

   Agree on a publication date with the CNA. We appreciate a heads-up so we can
   be ready to publish the CVE promptly. You can use the GHSA comments to
   coordinate; comments remain private even after the advisory is published.

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
    and [Hex.pm](https://hex.pm/). In the near future, `mix deps.get`,
    `rebar3 deps get`, and `gleam deps download` will warn users
    when they install a package with a known vulnerability.

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

## 5. Timelines & Embargo

> **Note:** **Do not make anything public before the advisory is published.** This includes public Pull Requests, commits to main, public issues, blog posts, social media posts, or any other public communication referencing the vulnerability. **If information becomes public, our disclosure timeline immediately shifts to 24 hours or less**, regardless of whether a patch is ready.

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

## 6. What Not to Do

The following actions break the embargo and can cause the CVE to be published
immediately, even if no patch is available:

- Opening a public Pull Request that references or fixes the vulnerability
- Merging a security fix to `main` or any public branch before the advisory is published
- Including the CVE ID or vulnerability details in a public commit message
- Discussing the issue in a public GitHub issue or discussion
- Announcing a "security release" before the advisory is ready
- Posting about the vulnerability on social media, a blog, or a mailing list

## 7. Feedback

Once you are through the process, we would love to hear your feedback on this document.
If anything took extra time to figure out or required clarification, we want to know so
we can make it clearer for future maintainers. You can reach us via the
[Contact](/contact) page, or send a Pull Request directly to
[this file on GitHub](https://github.com/erlef-cna/website/blob/main/maintainer-process.md).

## 8. Further Resources

- [Contact](/contact) — Reach out to the CNA
- [CVE Criteria](/cve-criteria) — What qualifies for a CVE
- [Security Policy](/security-policy) — Full disclosure policy & timelines
- [EEF Security WG Guide](https://security.erlef.org/security_vulnerability_disclosure/) — Vulnerability handling best practices
