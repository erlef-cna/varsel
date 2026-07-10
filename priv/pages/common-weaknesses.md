%{
  title: "Common Weaknesses",
  description: "The most common CWE weakness classes across Erlang ecosystem CVEs"
}
---

The chart below shows the most common weakness classes found in vulnerabilities
across the Erlang ecosystem. Understanding which weakness types recur most often
helps library authors and application developers focus their security efforts
where they matter most.

Each CVE is mapped to its [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
class using the CWE hierarchy. Individual weakness types (Base and Variant level)
are rolled up to their nearest **Class-level** ancestor, so related weaknesses are
grouped together rather than scattered across many small slices. Weakness classes
with fewer than 2 CVEs are folded into "Other". Each CVE is counted once per unique
class it references.
