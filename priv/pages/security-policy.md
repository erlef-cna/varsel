%{
  title: "Security Policy",
  description: "The EEF CNA's security policy for vulnerability reporting and CVE assignment"
}
---

## Introduction

This document outlines the security policy for our CVE Numbering Authority
(CNA). It details our scope, contact methods, disclosure processes, report
formats, dispute handling procedures, and references to our Root CNA's policies.

## 1. Scope

Our detailed scope is defined in our [Scope Definition](/scope).

## 2. Contact Methods

We encourage security researchers and members of the community to report
vulnerabilities through the contact methods outlined on our
[Contact Page](/contact).

## 3. Disclosure Process

### 3.1. Initial Response

- **Acknowledgment:** We will acknowledge all vulnerability reports within **two
  business days**.
- **Assessment:** Reports will be evaluated for validity and impact within **two
  business days** of acknowledgment.

### 3.2. Handling Different Types of Vulnerabilities

#### 3.2.1. Publicly Disclosed Vulnerabilities

- **Definition:** Vulnerabilities that are publicly known or actively exploited
  in the wild.
- **Action:** We will publish information about publicly disclosed
  vulnerabilities within **24 hours or less**.

#### 3.2.2. Vulnerabilities in Projects Participating in the CNA

- **Pre-Arranged Contacts:** We have established direct communication channels
  with these projects to ensure timely coordination. This includes Elixir,
  Erlang, Erlang Ecosystem Foundation, Gleam, and Hex.
- **Process:** Projects with prior agreements may have tailored processes for
  vulnerability handling, while always adhering to the timeframes outlined in
  this document.

#### 3.2.3. Non-Public Vulnerabilities in Hex.pm Packages

- **Contacting Maintainers:**
  - We will attempt to reach out to the package maintainers by retrieving their
    email addresses from the Hex.pm user database. Please note that these emails
    may not be publicly available.
  - Maintainers are encouraged to establish pre-arranged contact channels with
    us for faster communication.
- **Response Timeframe:**
  - **14 Days:** If maintainers do not respond within 14 days, we will proceed
    to publish the CVE.
  - **Coordination Period:** We allow up to **3 months** for coordinated
    disclosure, depending on the severity and impact.
- **Action:** We will follow the project's specific security policies outlined
  in their `SECURITY.md` files, provided they align with our maximum
  timeframes and the maintainers respond within **14 days** of our initial
  communication.

### 3.3. Maintainer Coordination

- **Embargo Period:** We aim to publish vulnerabilities as soon as possible. The
  maximum embargo period is **3 months**.
- **No Reply Scenario:** If maintainers do not respond within the specified
  timeframes, we will publish the CVE unilaterally.

## 4. Report Format

When reporting a vulnerability, please include the following information to help
us assess and address the issue promptly:

- **Type of Issue:** Brief description (e.g., buffer overflow, SQL injection).
- **Affected Project:** Project URL or Hex.pm Package Name.
- **Affected Version(s):** Specific versions (e.g., `v1.2.3`) or commit SHAs.
- **Affected Files/Paths:** Specific source files or paths involved.
- **Configuration Details:** Any special configurations required to reproduce
  the issue.
- **Reproduction Steps:** Step-by-step instructions to replicate the
  vulnerability.
- **Proof-of-Concept or Exploit Code:** If available, code that demonstrates the
  vulnerability.
- **Impact Assessment:** Potential impact and how the issue might be exploited
  by an attacker.
- **Your Contact Information:** Optional, but helpful if we need further
  clarification.

## 5. Dispute Handling

### 5.1. Dispute Resolution Process

- **Acknowledgment:** We will acknowledge disputes within **three business
  days**.
- **Initial Decision:** Within **one week** after acknowledgment, we will
  provide a decision or request an extension.
- **Extended Review:** If extended, we will make a final decision within **14
  days**.
- **Internal Review:** Disputes will trigger an internal referendum as per our
  [Governance Documentation](https://github.com/erlef-cna/.github/blob/main/GOVERNANCE.md).

### 5.2. Escalation

If the disputing party is unsatisfied with our final decision, they may
escalate the matter to our Root CNA, initiating a new dispute cycle.

## 6. References to Root CNA Policies

We adhere to the following policies and guidelines:

- **CVE Numbering Authority Operational Rules:**
  [CNA Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules/#section_4-4_CNA_Judgment)
- **CVE Program Policy and Procedure for Disputing a CVE Record:**
  [Policy and Procedure](https://www.cve.org/Resources/General/Policies/CVE-Record-Dispute-Policy.pdf)

## 7. Publication of CVEs

### 7.1. CVE Publication

- **CVE Database:** All assigned CVEs will be published through the official CVE
  channels.
- **Project Website:** CVEs will also be listed on our website at
  [cna.erlef.org/cves](https://cna.erlef.org/cves).

### 7.2. Notification

- **Community and Stakeholders:** We will notify relevant parties through our
  publication process. Project maintainers are responsible for additional communications to their users.

## Additional Information

### Handling of `SECURITY.md` Files

- **Compliance:** We will adhere to the instructions in a project's
  `SECURITY.md` file whenever feasible.
- **Limitations:** We will only follow the project's security policies if the
  maintainers respond within **14 days** of our initial communication. We will
  not honor disclosure timelines exceeding our maximum timeframes and will
  proceed with publishing publicly disclosed vulnerabilities promptly.
- **Maintainer Communication:** Project maintainers are encouraged to reach out
  to us for clarity or to establish preferred communication channels.

### Definition of Public Vulnerabilities

- **Public Vulnerabilities:** Issues that have already been disclosed publicly,
  such as those discussed in public issue trackers or actively exploited in the
  wild.

### CVE Assignment Criteria

For detailed guidance on what constitutes a CVE-worthy vulnerability,
including ecosystem-specific considerations for internal modules, see our
[CVE Assignment Criteria](/cve-criteria) page.

### Communication with Reporters

- **Acknowledgment Receipts:** Reporters will receive an acknowledgment within
  **two business days**.
- **Status Updates:** We will inform reporters when the vulnerability is
  published.
- **Confidentiality:** We will not disclose communications with maintainers to
  reporters, except to facilitate direct contact if both parties agree.
- **Credit:** We will ask reporters if they wish to be credited, provided they
  are the first to report the vulnerability.

*This policy is effective as of 2025-05-13, last updated 2026-03-23, and is subject to change.*
