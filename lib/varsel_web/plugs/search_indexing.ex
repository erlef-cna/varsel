# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
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

  Otherwise it serves the normal allow-everything `robots.txt` and adds no
  header. Runs as an endpoint plug, ahead of the router, so it covers the HTML,
  JSON, GraphQL and MCP surfaces uniformly.
  """
  @behaviour Plug

  import Plug.Conn

  @robots_disallow """
  # Test deployment — not for indexing.
  User-agent: *
  Disallow: /
  """

  @robots_allow """
  User-agent: *
  Disallow:
  """

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{request_path: "/robots.txt", method: method} = conn, _opts) when method in ~w(GET HEAD) do
    body = if indexing_blocked?(), do: @robots_disallow, else: @robots_allow

    conn
    |> maybe_put_robots_tag()
    |> put_resp_content_type("text/plain")
    |> send_resp(200, body)
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
end
