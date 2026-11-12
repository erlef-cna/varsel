# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.SearchIndexing do
  @moduledoc """
  Controls whether search engines may index the site.

  On a test deployment (`:test_deployment?` is true — the default, see
  `config/runtime.exs`) indexing is fully blocked. This plug then:

    * answers `GET`/`HEAD /robots.txt` with a "disallow everything" body, and
    * adds `X-Robots-Tag: noindex, nofollow, noarchive` to every response so
      crawlers that ignore `robots.txt` (and non-HTML responses like the JSON
      API) are still told not to index or follow.

  Otherwise it serves a `robots.txt` that admits the public pages, disallows the
  auth, API and sign-in-only paths, and points crawlers at `/sitemap.xml`. It
  adds no header. Runs as an endpoint plug, ahead of the
  router, so it covers the HTML, JSON, GraphQL and MCP surfaces uniformly.
  """
  @behaviour Plug

  use VarselWeb, :verified_routes

  import Plug.Conn

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{request_path: "/robots.txt", method: method} = conn, _opts) when method in ~w(GET HEAD) do
    conn
    |> maybe_put_robots_tag()
    |> put_resp_content_type("text/plain")
    |> send_resp(200, robots(indexing_blocked?()))
    |> halt()
  end

  def call(conn, _opts), do: maybe_put_robots_tag(conn)

  defp maybe_put_robots_tag(conn) do
    if indexing_blocked?() do
      put_resp_header(conn, "x-robots-tag", "noindex, nofollow, noarchive")
    else
      conn
    end
  end

  defp indexing_blocked?, do: Application.fetch_env!(:varsel, :test_deployment?)

  # Test deployments block everything; production allows everything and points
  # crawlers at the sitemap.
  defp robots(true) do
    """
    # Test deployment — not for indexing.
    User-agent: *
    Disallow: /
    """
  end

  defp robots(false) do
    """
    User-agent: *
    Disallow: /auth/
    Disallow: /sign-in
    Disallow: /sign-out
    Disallow: /register
    Disallow: /reset
    Disallow: /password-reset/
    Disallow: /confirm_new_user/
    Disallow: /magic_link/
    Disallow: /oauth
    Disallow: /.well-known/oauth-
    Disallow: /settings/
    Disallow: /cases
    Disallow: /reports
    Disallow: /report
    Disallow: /users
    Disallow: /notifications
    Disallow: /cves/manage/
    Disallow: /api/
    Disallow: /gql
    Disallow: /mcp
    Disallow: /ws/
    Disallow: /live/
    Disallow: /*.json$

    Sitemap: #{url(~p"/sitemap.xml")}
    """
  end
end
