%{
  title: "Record Conventions",
  description: "House conventions for descriptions, CVSS scoring, CWE/CAPEC classification, credits, references, and the optional fields"
}
---

These conventions keep the CNA's records consistent. The
[machine-readable checklist](https://github.com/erlef-cna/varsel/tree/main/skills)
the [AI tooling](/guide/ai-tooling) runs encodes the same rules; this page is
the human-readable form.

## Descriptions

A description is a report, not a blog post. Target 100 to 150 words, hard
ceiling 250, two paragraphs at most and often one.

Open with the standard CVE summary sentence, our convention:

> [PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] allows [ATTACKER] to
> [IMPACT] via [VECTOR]

Drop the placeholders that do not apply rather than padding them out. The
rest of paragraph one says what the flaw actually is and who can trigger it.
Add a second paragraph only when the mechanism is not obvious from the
summary, or to rule out a more severe reading. Never a third.

Style rules, applied to every prose field:

- Write for a security-oriented audience in prose, not bullet lists.
- Inline code in backticks for paths, functions, and identifiers. No code
  blocks; describe code in prose, naming the file and the function.
- No affected versions in the description. Varsel appends the
  "This issue affects …" sentence, so writing it yourself publishes it twice.
- No other CVE IDs; name the vulnerability class instead.
- `TODO` marks any value not yet known, in URLs and prose alike. Never
  paraphrase it, and never write "no fix available": records are only
  published once a fix exists.
- Cut hedges, intensifiers, and background a security reader already has.

Varsel renders both the plain-text and the HTML form of each prose field from
the markdown, so write markdown once and check both on the case's **CVE**
tab.

## CVSS

The case carries a CVSS v4.0 **vector**; the numeric score and severity
bucket are derived from it at render time. Score the Base metrics only, with
a one-sentence rationale per metric in the proposal reasoning, and keep both
the score and the reasoning out of the description.

The metric that most often goes wrong is Attack Vector:

- **Network only if the vulnerable component itself handles network
  traffic**: a web framework, an HTTP server, a protocol library. A
  general-purpose library is Local even when an application could expose it
  over the network.
- Within a network-handling library, **decoder and encoder bugs score
  differently**: a parser of bytes arriving off the wire is Network; an
  encoder runs on whatever the application passes it, so it is Local, since
  the attacker first has to get the application to call it. When in doubt:
  does the attacker send bytes, or get the application to pass a string?

Subsequent System impact (SC/SI/SA) stays None unless the impact meaningfully
extends beyond the vulnerable component.

## CWE and CAPEC

Pick the CWE for the **root cause**, not the impact, at the most specific
level that fits: Base rather than a broad Class or an over-narrow Variant.
One CWE is the norm; a second needs a genuinely distinct root cause.

Pick the CAPEC by **attack mechanism**, starting from the patterns MITRE maps
to the chosen CWE. Several CAPECs are fine when several distinct techniques
exploit the weakness.

The CWE and the CAPEC should agree. A CAPEC from a weakness family you
already ruled out when picking the CWE usually means one of the two is
wrong; re-pick both before settling for the mismatch. The same goes for
earlier cases on the same package: if the evidence points elsewhere, do not
copy their classification just to stay consistent.

## Credits

The roles are the CVE record format's, with their meanings:

- `finder` identified the vulnerability.
- `reporter` reported it to the vendor or the CNA.
- `analyst` validated the vulnerability, its accuracy, or its severity.
- `coordinator` facilitated the coordinated response process.
- `remediation developer` prepared the fix or other remediation.
- `remediation reviewer` reviewed the fix for effectiveness and completeness.
- `remediation verifier` tested the vulnerability or its remediation.
- `tool` names a tool used in discovering the vulnerability.
- `sponsor` supported the identification or remediation work.
- `other` covers anything else.

Give each person every role that applies. GHSA allows only one role per
person, so an advisory usually understates them; the CVE record has no such
limit, and several roles per person is the common case.

Two more rules:

- `name` holds the full real name with its correct diacritics, nothing else.
  The affiliation goes in `organization`; Varsel renders the two together, so
  a name with the organization appended publishes it twice. Fall back to the
  bare handle only when the real name is genuinely unknown.
- Check how a person was credited on earlier records before inventing a new
  spelling.

## References

References are ordered: the vendor advisory comes first (a GHSA is tagged
`vendor-advisory, related`), and OTP records carry the
[OTP version-scheme page](https://www.erlang.org/doc/system/versions.html#order-of-versions).
The `patch` reference is derived from the fix commits, so add one by hand
only when there is no fix commit to point at. Add further references only
when they give useful context; skip aggregators that just point back at this
same record.

## Workarounds, Configurations, Solutions

All three fields are optional, and **omitting them is the default**:

- **Workarounds** name a real mitigation available *without upgrading*:
  disabling the affected feature, avoiding the vulnerable API, a
  configuration change that closes the hole. Never "apply the patch", never
  "upgrade", and never "There are no workarounds"; omit instead.
- **Configurations** appear only when specific deployment conditions make the
  vulnerability reachable. Unconditional issues have none.
- **Solutions** appear only when remediation goes beyond upgrading, which is
  rare.

A workaround is advice users act on, so test it before publishing it: run the
exploit with the mitigation applied and confirm it no longer succeeds.

## Internal Notes

The internal notes field holds whatever helps the next human or agent working
the case: reproduction status, how the boundary commits were established,
ruled-out alternatives, dead ends. It is never published.

## Verifying Before Review

Before sending a case to review, refresh the
[derivation](/guide/affected-versions), open the case's **Publication** tab,
and clear everything it flags: publish blockers are hard stops, and the
built-in validation (CVE schema, cvelint, and the hex.pm package check) must
pass. Then cross-check the rendered record on the **CVE** tab against the
vendor advisory one last time:
version ranges, credits including pending ones, and any `TODO` the advisory
has since resolved.
