# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.PublicResource do
  @moduledoc """
  Drops the default `cross-origin-resource-policy: same-site` header (set for
  every response in `VarselWeb.Plugs.SecurityHeaders`) from responses that are
  public, machine-readable data meant to be fetched cross-origin from anywhere:
  the CVE/OSV JSON API and the Atom/RSS feeds.

  The public data surface is spread across actions that also serve HTML or
  redirects (e.g. `/cves/<id>` renders HTML but `/cves/<id>.json` renders JSON
  from the *same* controller action), so this keys off the response
  content-type at send time rather than the route: CORP is removed for JSON and
  feed (Atom/RSS) responses, and left in place for everything else, including
  HTML detail pages served by the same controllers.
  """
  @behaviour Plug

  import Plug.Conn

  @public_types ["application/json", "application/atom+xml", "application/rss+xml"]

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    register_before_send(conn, fn conn ->
      if public_type?(conn) do
        delete_resp_header(conn, "cross-origin-resource-policy")
      else
        conn
      end
    end)
  end

  defp public_type?(conn) do
    case get_resp_header(conn, "content-type") do
      [content_type | _] -> Enum.any?(@public_types, &String.starts_with?(content_type, &1))
      [] -> false
    end
  end
end
