<!--
SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation

SPDX-License-Identifier: Apache-2.0
-->

---
name: cvss
description: Score a CVE using CVSS v4.0 metrics. Use when determining severity ratings or choosing the right CVSS v4.0 vector string for a vulnerability.
---

# CVSS v4.0 Scoring

Reference: https://www.first.org/cvss/v4.0/specification-document

Analyze the vulnerability and produce a CVSS v4.0 **vector string** with a one-line rationale per metric. Varsel derives the numeric base score and severity bucket from the vector once it lands on the case (via a `set` proposal on `cvss_v4`), so your job is to get the vector right — you do not compute the number yourself.

## Metric Reference

### Attack Vector (AV)
**Only use Network if the vulnerable component itself directly handles network traffic** (e.g. a web framework, HTTP server, network protocol library). A general-purpose library (e.g. a decimal math lib, JSON parser) is Local even if an app could theoretically expose it over the network.

**Within a network-handling library, encoders vs decoders split:**
- **Encoder bugs are AV:L.** An encoder runs on whatever the application passes in as arguments. The attacker has to first influence those arguments through application-level code paths (e.g. method/target injection in `Mint.HTTP.request/5`, filename in `Req`'s multipart form encoder). That is an application-reachability problem, not a network one.
- **Decoder/parser bugs that process bytes off the network are AV:N.** A decoder runs on whatever arrives over the wire from the remote peer (e.g. HTTP/2 frame parsers, response `Content-Length` parsers, response-body decompressors). The attacker reaches it by speaking the protocol.

When in doubt: ask "does the attacker reach this by sending HTTP bytes, or by getting the application to pass a string?" The former is AV:N, the latter is AV:L.

| Value | Description |
|-------|-------------|
| N — Network | The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. |
| A — Adjacent | The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level to a logically adjacent topology (e.g. same subnet, Bluetooth, NFC). |
| L — Local | The vulnerable system is not bound to the network stack and the attacker's path is via read/write/execute capabilities. |
| P — Physical | The attack requires the attacker to physically touch or manipulate the vulnerable system. |

### Attack Complexity (AC)
| Value | Description |
|-------|-------------|
| L — Low | The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention. |
| H — High | The successful attack depends on evading or circumventing security-enhancing techniques that would otherwise hinder it. |

### Attack Requirements (AT)
| Value | Description |
|-------|-------------|
| N — None | The successful attack does not depend on the deployment and execution conditions of the vulnerable system. |
| P — Present | The successful attack depends on the presence of specific deployment and execution conditions that enable the attack. |

### Privileges Required (PR)
| Value | Description |
|-------|-------------|
| N — None | The attacker is unauthenticated prior to attack, and requires no access to settings or files. |
| L — Low | The attacker requires privileges typically limited to settings and resources owned by a single low-privileged user. |
| H — High | The attacker requires significant (e.g. administrative) control over the vulnerable system. |

### User Interaction (UI)
| Value | Description |
|-------|-------------|
| N — None | The vulnerable system can be exploited without interaction from any human user other than the attacker. |
| P — Passive | Successful exploitation requires limited interaction by the targeted user with the system and the attacker's payload. |
| A — Active | Successful exploitation requires a targeted user to perform specific, conscious interactions with the system and the attacker's payload. |

### Vulnerable System Impact (VC / VI / VA)
| Value | Description |
|-------|-------------|
| H — High | Total loss of confidentiality / integrity / availability within the Vulnerable System. |
| L — Low | Some loss, but the attacker does not have full control / performance reduced but service not fully denied. |
| N — None | No loss within the Vulnerable System. |

### Subsequent System Impact (SC / SI / SA)
Only set non-None if the vulnerability meaningfully impacts systems beyond the vulnerable component itself.

| Value | Description |
|-------|-------------|
| H — High | Total loss of confidentiality / integrity / availability within the Subsequent System. |
| L — Low | Some loss, but no full control / performance reduced but not fully denied. |
| N — None | No loss within the Subsequent System, or all impact is constrained to the Vulnerable System. |

### Supplemental metrics (do NOT set)
We only score the Base metrics. Do not set `Automatable`, `Recovery`, `Safety`, `valueDensity`, `vulnerabilityResponseEffort`, or `providerUrgency`.

## Steps

1. Read the case (or advisory) to understand the vulnerability.
2. For each Base metric, choose a value and state a one-sentence rationale.
3. Assess Subsequent System Impact — only non-None if there is meaningful impact beyond the vulnerable component.
4. Produce the vector string:
   `CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_`

## Output

Present:
- The vector string.
- A short rationale table (metric → chosen value → reason).

Then, in the `/new-cve` flow, land it on the case as a proposal (Varsel computes the score/severity from the vector):

```
create_case_proposal(input: {
  case_id: <id>, target: "case", operation: "set",
  field_name: "cvss_v4",
  proposed_value: {"value": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
  reasoning: "<per-metric rationale>"
})
```