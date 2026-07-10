%{
  title: "Coordinator Process",
  description: "How to sign up as a volunteer CNA coordinator and handle vulnerability reports"
}
---

With an unprecedented wave of vulnerability reports, we need help. If you have
security knowledge and want to contribute to a safer Erlang ecosystem, this page
is for you.

## 1. Support the CNA

Running a CNA takes time and resources. There are two ways to help:

- **Financially:** The EEF depends on sponsors to fund this work.
  Consider [sponsoring the EEF](https://erlef.org/sponsors).
- **As a volunteer coordinator:** Handle reports, triage vulnerabilities, and
  coordinate disclosures with maintainers. Read on to find out how.

## 2. Sign Up as a Coordinator

:::steps
1. **Join the EEF and its Slack**

   [Become an EEF member](https://members.erlef.org/join-us) and join the
   community Slack workspace.

2. **Announce yourself on #cna-public**

   Use the *"Sign Up as a CNA Coordinator"* workflow in the `#cna-public` Slack
   channel to let us know you want to help.

   ![Slack channel showing Reserve a CVE ID and Sign Up as a CNA Coordinator workflow buttons](/images/coordinator-process/slack-workflows.png)

3. **Tell us your specialities**

   Domain knowledge is valuable. If you know the details and RFCs around SSH,
   TLS, cryptography, or any other area, let us know. It helps us route reports
   to the right people.

4. **Share your contact details**

   Tell us your email address and GitHub handle so we can reach you privately.
:::

## 3. Working with People

The technical side of coordination is learnable. The human side is often harder.

Receiving a CVE report is stressful for most maintainers. Open source projects are
frequently personal labours of love, and a security vulnerability can feel like a
public indictment. Many maintainers will be genuinely grateful for your help, but
others may react with anxiety, defensiveness, or even hostility. Shame is common.
People under stress make hasty decisions, sometimes exactly the kind that break the
embargo.

Your job is not just to communicate facts, but to help maintainers get grounded and
make good decisions. Some things that help:

- Acknowledge that receiving this kind of report is hard.
- Be clear that the goal is to protect their users, not to criticise their work.
- Explain the process and timelines calmly and early, so there are no surprises.
- When a maintainer is moving too fast or about to do something risky, slow them down
  rather than just flagging the problem.

If a maintainer lashes out, stay friendly and professional. Do not match their tone.

If communication is repeatedly going in a bad direction and you are not able to get
things back on track, involve a CNA Point of Contact before anything escalates. Do
not let a difficult conversation drag on without support.

## 4. Required Knowledge

You do not need to know everything upfront, but these are the core concepts you will
work with on every report.

- **[CVSS v4.0](https://www.first.org/cvss/v4.0/user-guide):** Every vulnerability is
  scored using CVSS. This measures severity across dimensions like attack vector,
  complexity, and impact. Read the user guide before handling your first report.

- **[CWE](https://cwe.mitre.org/about/new_to_cwe.html):** Every vulnerability is
  classified by weakness type using CWE (Common Weakness Enumeration). For example,
  CWE-79 is Cross-site Scripting and CWE-22 is Path Traversal.

- **[CAPEC](https://capec.mitre.org/about/new_to_capec.html):** Every vulnerability is
  assigned an attack pattern using CAPEC (Common Attack Pattern Enumeration and
  Classification). This describes how an attacker would exploit the weakness.

- **[Package URL](https://packageurl.org/):** Affected software is identified using
  Package URLs (purl). For example, `pkg:hex/phoenix` identifies the `phoenix` package
  on Hex.pm.

## 5. Before Your First Report

Take some time to get familiar with how our CVE records look in practice. Browse the
[published CVEs](/cves) on this site to see the level of detail we include in titles,
descriptions, affected version ranges, and credits.

For the underlying data format, refer to the
[CVE JSON schema](https://github.com/CVEProject/cve-schema). All our records follow
this schema, and the [cna-staging repository](https://github.com/erlef-cna/cna-staging)
contains tooling to validate and format them.
[Vulnogram](https://vulnogram.github.io/) is a useful tool for visually editing and
validating CVE JSON records.

## 6. The Coordination Process

:::steps
1. **Receive the Report**

   We will contact you privately with a vulnerability report. Treat all details
   as confidential until the advisory is published.

2. **Triage**

   Determine whether the report warrants a CVE. Check our
   [CVE Criteria](/cve-criteria) page for guidance.

   - **If yes:** use the *"Reserve a CVE ID"* workflow in `#cna-public` on Slack, or ask a CNA Point of Contact directly.
   - **If no:** it may still be a bug worth reporting. Open an issue or send a PR to the affected project instead.

   ![Slack channel showing Reserve a CVE ID and Sign Up as a CNA Coordinator workflow buttons](/images/coordinator-process/slack-workflows.png)

3. **Find Contact Information**

   Work through these options in order to find how to reach the maintainer:

   - Check for a `SECURITY.md` file in the repository.
   - Check if GitHub Private Vulnerability Reporting is enabled.
   - Look for an email on the Hex.pm user profile or GitHub profile.
   - If no email is public, check the git log; commit author emails are often
     available there.

   When coordinating via email, always CC **cna@erlef.org** on all communications.

4. **Write a Proof of Concept**

   Demonstrate that the vulnerability actually exists with a minimal reproducible
   example. This confirms the report is valid and gives the maintainer something
   concrete to work with, and it also informs accurate CVSS scoring.

5. **Assess CVSS, CWE, and Affected Versions**

   Score the vulnerability using CVSS v4.0, identify the CWE weakness type, and
   determine which version ranges are affected.

6. **Report to the Maintainer**

   Your report should include:

   - A description of the vulnerability
   - The proof of concept
   - The CVE ID
   - CVSS score and CWE classification
   - Affected packages and version ranges (including any related artifacts such
     as Docker images)
   - A link to the [Maintainer Process](/maintainer-process) page

   If you have a patch ready, include it as well.

7. **Coordinate with the Maintainer**

   Work with the maintainer to get a patch written, reviewed, and a release date
   agreed. Refer them to the [Maintainer Process](/maintainer-process) page for
   step-by-step guidance.

8. **Prepare the Public Summary**

   The initial report contained full details including a proof of concept. The
   public advisory should be concise. Write a public-facing summary following the
   [GitHub Advisory](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)
   format: a short description of the vulnerability, its impact, and the affected
   versions. Leave out exploit details and internal investigation notes. See
   [this advisory](https://github.com/ex-aws/ex_aws_sns/security/advisories/GHSA-8jgf-23q5-x7xx)
   as an example.

9. **Observe Timelines**

   Keep these timeframes in mind throughout the process:

   - **Publicly known or actively exploited vulnerabilities:** publish
     within 24 hours.
   - **New reports:** contact the maintainer within 2 business days.
   - **Maximum embargo:** 3 months from the initial report.
   - **Maintainer non-response:** if there is no reply within 1 week,
     follow up via alternative channels. If there is still no response after 14 days,
     we will publish without maintainer involvement.

10. **Prepare the CVE Record**

    Prepare the CVE JSON record and send it to the CNA Points of Contact privately
    for review before publication.

11. **Trigger Publication**

    Once the maintainer has merged the fix, released a new version, and published
    the advisory, notify the CNA Points of Contact to publish the CVE.
:::

## 7. CNA Internal Process & Tooling

The internal CNA workflow is documented in the
[cna-staging repository](https://github.com/erlef-cna/cna-staging). This includes
scripts for formatting and validating CVE records, converting to OSV format, and
automation workflows.

The repository also contains a set of Claude Code skills that can assist with
common coordinator tasks:

- [new-cve](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/new-cve/SKILL.md): step-by-step workflow for creating a CVE record
- [cvss](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/cvss/SKILL.md): CVSS v4.0 scoring
- [find-cwe](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/find-cwe/SKILL.md): CWE classification
- [find-capec](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/find-capec/SKILL.md): CAPEC attack pattern identification
- [find-intro-commit](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/find-intro-commit/SKILL.md): locate the commit that introduced a vulnerability
- [summarize-cve](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/summarize-cve/SKILL.md): generate a technical CVE summary
- [verify](https://github.com/erlef-cna/cna-staging/blob/main/.claude/skills/verify/SKILL.md): validate a CVE record before submission

> **Note:** AI can be very helpful for these tasks, but every result must be verified by a human before submission. Do not rely on AI output without checking it yourself.

## 8. Further Resources

- [Contact](/contact) — Reach the CNA Points of Contact
- [CVE Criteria](/cve-criteria) — What qualifies for a CVE
- [Maintainer Process](/maintainer-process) — Share this with maintainers
- [Security Policy](/security-policy) — Full disclosure policy & timelines
- [CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide) — Learn to score vulnerabilities
- [New to CWE](https://cwe.mitre.org/about/new_to_cwe.html) — Learn weakness classification
- [New to CAPEC](https://capec.mitre.org/about/new_to_capec.html) — Learn attack pattern classification
- [Package URL](https://packageurl.org/) — Package identifier format
- [CVE JSON Schema](https://github.com/CVEProject/cve-schema) — Official CVE record format
- [Vulnogram](https://vulnogram.github.io/) — Visual CVE JSON editor
