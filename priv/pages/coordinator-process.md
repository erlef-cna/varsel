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

   ![Slack channel showing the Sign Up as a CNA Coordinator workflow button](/images/coordinator-process/slack-workflows.png)

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
descriptions, affected version ranges, and credits. The
[Record Conventions](/guide/record-conventions) page spells out the house rules those
records follow: how to write descriptions, score CVSS, classify, and credit people.

For the underlying data format, refer to the
[CVE JSON schema](https://github.com/CVEProject/cve-schema). All our records follow
this schema, and this site validates them against it before publication (see
[§7](#7-cna-internal-process--tooling)).

## 6. The Coordination Process

We do not expect you to write the record by hand. Connect your local AI
agent to this site over MCP ([API Access](/api-access)), and use the Varsel
skills ([AI Tooling](/guide/ai-tooling)) for the writing and research work:
triage, the record, CVSS, CWE and CAPEC, the affected versions, and the final
check. The agent proposes, and you review and decide on the case page.

:::steps
1. **Get Assigned to a Case**

   A CNA Point of Contact assigns you to a reported case while it is still
   *Submitted*. You are notified, and the case shows on your [Cases](/cases)
   board. Treat everything on it as confidential until the advisory is
   published.

2. **Triage**

   Check the report against our [CVE Criteria](/cve-criteria). Reproduce the
   claim with a minimal proof of concept: it confirms the report, gives the
   maintainer something concrete, and informs the CVSS score. Then decide on
   the case page:

   - **Accept** the case, and it opens as a draft.
   - **Reject** it with a reason. A report that is not a vulnerability may
     still be a bug worth an issue or a PR on the affected project.
   - **Merge** it into a case for the same finding. You need to be on both
     cases.
   - **Split** off a new case for each further finding the report holds.

   The `triage-report` skill checks the claim, looks for duplicates, and
   posts a recommendation on the case. Mark the case *Under triage* while you work on it, so others see it is
   taken.

   ![A submitted case with Accept case, Under triage, and the menu with split, merge and reject](/images/coordinator-process/case-triage.png)

3. **Take a CVE ID**

   Once the case is accepted, take the next free CVE ID on the case yourself.

4. **Fill In the Record**

   The record needs a description, a CVSS v4.0 score, the CWE and CAPEC, the
   affected versions, and credits. The `new-case` skill drafts all of it as
   proposals, and `verify` checks the result. Review every proposal before you
   accept it. [Filing a CVE](/guide/filing-a-case) walks through the case, and
   [Record Conventions](/guide/record-conventions) is the house style.

5. **Bring the Maintainer In**

   Invite the maintainers to the case by their GitHub or Hex.pm handles, and
   mark them as *Maintainer*. Their invite email asks them to respond and
   links the [Maintainer Process](/maintainer-process).

   When the repository has GitHub Private Vulnerability Reporting enabled,
   also report the vulnerability from the case's **GitHub** tab. It sends the
   maintainers a private vulnerability report with everything the case
   states, and links the advisory GitHub opens to the case. When an advisory
   already exists, link it there instead. Ask the maintainers to install the
   EEF CNA GitHub App, so the advisory and the case stay in sync.

   Coordinate on the advisory or in the case comments.

6. **Coordinate the Fix**

   Work with the maintainer to get a patch written, reviewed, and a release
   date agreed. The [Maintainer Process](/maintainer-process) gives them
   step-by-step guidance.

7. **Prepare the Public Summary**

   The initial report contained full details including a proof of concept. The
   public advisory should be concise. Write a public-facing summary following the
   [GitHub Advisory](https://docs.github.com/en/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database)
   format: a short description of the vulnerability, its impact, and the affected
   versions. Leave out exploit details and internal investigation notes. See
   [this advisory](https://github.com/ex-aws/ex_aws_sns/security/advisories/GHSA-8jgf-23q5-x7xx)
   as an example.

8. **Request Approval**

   Request review as soon as the record is complete and
   [verifies clean](/guide/record-conventions). Do not wait for the patch or
   the release: an early request gives the Points of Contact ample time to
   review. A Point of Contact sends the case back with findings, or approves
   it. Late details, such as the fixed version, still fit after approval: a
   Point of Contact adds them, or you reopen the case.

   ![A draft case with its Request review button](/images/coordinator-process/case-request-review.png)

9. **Observe Timelines**

   Keep these timeframes in mind throughout the process:

   - **Publicly known or actively exploited vulnerabilities:** publish
     within 24 hours.
   - **New reports:** contact the maintainer within 2 business days.
   - **Maximum embargo:** 3 months from the initial report.
   - **Maintainer non-response:** if there is no reply within 1 week,
     follow up via alternative channels. If there is still no response after 14 days,
     we will publish without maintainer involvement.

10. **Publication**

    Only a CNA Point of Contact publishes. Once the maintainer has released
    the fix and published the advisory, a Point of Contact publishes the CVE
    from the approved case. Tell them when the disclosure date is set.
:::

## 7. CNA Internal Process & Tooling

CNA processes are facilitated by [Varsel](https://github.com/erlef-cna/varsel),
the application this site runs on. It manages CVE records through their whole
lifecycle — reservation, drafting, publication to MITRE, and the derived OSV
feeds.

As a coordinator you work in it directly: sign in with GitHub or Hex.pm, and
once we grant you the `supporter` role (the app's name for the coordinator
job), you work the cases a Point of Contact assigns you: triage, CVE IDs,
records, and review requests. You can also open a case for a finding of your
own. The
[Varsel Guide](/guide) documents all of it; start with
[Filing a CVE](/guide/filing-a-case).

Varsel also ships a Claude Code plugin of skills covering common coordinator
tasks: scoring, classification, drafting, and validating a record before
submission. [AI Tooling](/guide/ai-tooling) covers installing the plugin and
connecting the MCP server; [API Access](/api-access) covers authentication
and automating your work with other tooling.

> **Note:** AI can be very helpful for these tasks, but every result must be verified by a human before submission. Do not rely on AI output without checking it yourself.

## 8. Further Resources

- [Contact](/contact) — Reach the CNA Points of Contact
- [CVE Criteria](/cve-criteria) — What qualifies for a CVE
- [Varsel Guide](/guide) — Working in the CNA's case tooling
- [API Access](/api-access) — GraphQL and MCP access to the tooling
- [Maintainer Process](/maintainer-process) — Share this with maintainers
- [Security Policy](/security-policy) — Full disclosure policy & timelines
- [CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide) — Learn to score vulnerabilities
- [New to CWE](https://cwe.mitre.org/about/new_to_cwe.html) — Learn weakness classification
- [New to CAPEC](https://capec.mitre.org/about/new_to_capec.html) — Learn attack pattern classification
- [Package URL](https://packageurl.org/) — Package identifier format
- [CVE JSON Schema](https://github.com/CVEProject/cve-schema) — Official CVE record format
