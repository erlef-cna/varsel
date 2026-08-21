%{
  title: "AI Tooling",
  description: "The MCP server and the Claude Code plugin that automate case filing, and the guardrails around them"
}
---

Filing a CVE means git archaeology, CVSS scoring, classification, and a lot
of convention-following. Varsel ships tooling that lets an AI agent do that
legwork, while every decision that matters stays with a human. It is there
for supporters and Points of Contact alike.

## The MCP Server

Varsel exposes a [Model Context Protocol](https://modelcontextprotocol.io)
server at `/mcp`. It carries the same data and case operations your role
allows in the UI: reading cases and records, searching the CWE and CAPEC
catalogs, proposing field changes, commenting, giving people access to a case
by their GitHub or Hex.pm handle, refreshing derivations, and running the
validators.

By design it carries **no** tools to accept or decline proposals, assign
roles, or publish. An agent working over MCP states facts as proposals; a
human reviews and accepts them in the UI.

See [API Access](/api-access) for how to connect a client and authenticate.
MCP clients handle the OAuth flow themselves, so pointing one at the URL and
approving the consent screen is the whole setup.

## The Claude Code Plugin

The [Varsel repository](https://github.com/erlef-cna/varsel) doubles as a
Claude Code plugin marketplace bundling the CNA's case-filing skills. From
Claude Code:

```
/plugin marketplace add erlef-cna/varsel
/plugin install varsel-poc@varsel
```

The skills drive the Varsel MCP, so connect and authenticate the MCP server
first (`/mcp` inside Claude Code shows the connection state).

## The Skills

| Skill | Purpose |
|-------|---------|
| `new-case` | The orchestrator: takes an advisory or a pasted report to a verified, review-ready case, calling the skills below on the way. |
| `cvss` | Produce a CVSS v4.0 vector; Varsel derives the numeric score. |
| `find-cwe` | Pick the CWE weakness classification from the catalog. |
| `find-capec` | Pick the CAPEC attack pattern, consistent with the CWE. |
| `find-intro-commit` | Git archaeology for the introducing commit SHA. |
| `verify` | Render the preview, run the validators, and walk the [convention checklist](/guide/record-conventions). |
| `summarize-cve` | A human-readable technical write-up of a case or published CVE. |

Each is invocable directly (for example `/verify`), and `new-case` is the one
to reach for when filing.

The skills stop where Varsel's own automation starts: version ranges, CPEs,
and per-channel version data are [derived from commit facts](/guide/affected-versions),
and formatting, schema validation, and the MITRE push are Varsel's job. The
agent's output is the facts, as proposals.

## Guardrails

Every change an agent makes is a proposal, and a human accepts it: agents
never self-approve, and CVE ID assignment, proposal acceptance, and
publishing happen in the UI only. The one direct write is case access: the
skills put the advisory's collaborators, the repository owner and the Hex.pm
package owners on a case as they file it, the same assignment or invite a
human would make by handle. Taking someone off a case stays in the UI. Treat
agent output as a draft: verify every score, classification, and boundary commit
before accepting the proposal that carries it, with the
[record conventions](/guide/record-conventions) as the checklist.
