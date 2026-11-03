%{
  title: "Data Licensing",
  description: "How EEF CNA vulnerability data is licensed, and how other CVE containers are handled"
}
---

## EEF CNA Content

All original vulnerability metadata authored and published by the EEF CNA is
licensed under **CC-BY 4.0 (Creative Commons Attribution 4.0 International)**.

This includes, in particular:

- EEF CNA **OSV records**
- the **CNA container** authored by the EEF CNA in CVE JSON records
- the **ADP container** authored by the EEF CNA in the CVE JSON record of an
  upstream CVE (see below)
- related original metadata published by the EEF CNA as part of its advisory
  process

You are free to share and adapt this material for any purpose, including
commercially, as long as you give appropriate credit. See the
[CC-BY 4.0 legal text](https://creativecommons.org/licenses/by/4.0/)
for details.

## Upstream CVEs

Packages in the Erlang ecosystem can vendor code from projects outside the EEF
CNA's [scope](/scope), such as a C library. The EEF CNA does not assign CVEs for
vulnerabilities in that code: the CNA responsible for the vendored project
assigns the CVE, and the EEF CNA publishes an enrichment of it for the affected
packages. We call such a CVE an upstream CVE. The CVE JSON record that the
EEF CNA serves for an upstream CVE is the record of the assigning CNA, with
the EEF CNA's enrichment added as an **ADP container**.

In such a record:

- the **CNA container** is the assigning CNA's content, not the EEF CNA's
- the **ADP container** with the EEF CNA's organization ID is the EEF CNA's
  content, licensed under CC-BY 4.0
- the **OSV record** (`EEF-CVE-…`) is derived from the EEF CNA's ADP
  container, and is licensed under CC-BY 4.0

The CVE page of an upstream CVE shows the assigning CNA's title and summary
for context. That text remains the assigning CNA's content.

## Other CVE Containers

A CVE record may contain containers from other organizations: the CNA
container of an upstream CVE, and ADP (Authorized Data Publisher) containers
in addition to the container authored by the EEF CNA.

Those **non-EEF containers** are **not** covered by the CC-BY 4.0 license above.

They remain subject to:

- the applicable **[CVE.org Terms of Use](https://www.cve.org/Legal/TermsOfUse)**
- the rights and terms of the **respective authors or publishers**

Where a CVE JSON record contains content from multiple sources, only the content
authored by the EEF CNA, in the **CNA container** of a CVE it assigned or in its
**ADP container** of an upstream CVE, is licensed under CC-BY 4.0 by the EEF CNA.

## Scope Clarification

For clarity:

- **EEF-authored OSV records**, including those for upstream CVEs: CC-BY 4.0
- **EEF-authored CNA container content in CVE JSON**: CC-BY 4.0
- **EEF-authored ADP container content in the CVE JSON of an upstream CVE**:
  CC-BY 4.0
- **CNA containers of upstream CVEs**: licensed under their respective terms
  and not relicensed by the EEF CNA
- **ADP containers of other organizations**: licensed under their respective
  terms and not relicensed by the EEF CNA

The EEF CNA only applies CC-BY 4.0 to vulnerability data for which it is the
author or rights holder.

## Questions

If you have questions about the licensing of EEF CNA data, please
[contact](/contact) the EEF CNA maintainers.
