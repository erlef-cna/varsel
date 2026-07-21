%{
  title: "API Access",
  description: "Machine access to the CNA data and tooling via GraphQL and MCP, authenticated with OAuth 2.1 or a personal API token"
}
---

## GraphQL

The GraphQL API is served at `/gql` and requires authentication: every
request must carry a bearer token. It exposes the published CVE data plus
the CVE lifecycle, case, and user-management operations your role allows.
Logged-in users can explore the schema in the interactive
[GraphiQL playground](/gql/playground). The published data alone is also
available without authentication as plain JSON under
[`/cves/index.json`](/cves/index.json) and [`/osv/all.json`](/osv/all.json).

```sh
curl -X POST %BASE_URL%/gql \
  -H "content-type: application/json" \
  -H "authorization: Bearer <token>" \
  -d '{"query": "{ listPublishedCves { cveId title } }"}'
```

## MCP

The [Model Context Protocol](https://modelcontextprotocol.io) server at
`/mcp` exposes the same data and lifecycle operations as tools for AI agents
such as Claude Code. A typical client configuration:

```json
{
  "mcpServers": {
    "eef-cna": {
      "type": "http",
      "url": "%BASE_URL%/mcp"
    }
  }
}
```

## Authenticating with OAuth 2.1

Both surfaces accept OAuth 2.1 access tokens. Clients register themselves
(dynamic client registration) and discover the authorization server through
the standard metadata documents at `/.well-known/oauth-authorization-server`
and `/.well-known/oauth-protected-resource`. MCP clients do all of this
automatically starting from the discovery challenge of an unauthenticated
request — point them at the MCP URL, approve the consent screen in your
browser, and you are done.

Access tokens are scoped per surface: `mcp` grants the MCP endpoint, `gql`
grants GraphQL. A token used on a surface whose scope it does not carry is
rejected with `403 insufficient_scope`.

## Personal API Tokens

For clients without OAuth support, create a personal access token under
[API Tokens](/settings/tokens) (login required) and send it as an
`Authorization: Bearer` header. These tokens act as you on both surfaces
without scope restrictions, so prefer OAuth where possible and give manual
tokens an expiry.

## Fair Use

Every registered user gets full API access. This is deliberately
permissive: it lets you automate your interactions with the CNA with the
tooling of your choice, including submitting vulnerability reports.
Please behave yourself — should this openness be abused, we will restrict
API access.