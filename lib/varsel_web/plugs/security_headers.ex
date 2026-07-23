# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.SecurityHeaders do
  @moduledoc """
  Sets response security headers that Phoenix's `put_secure_browser_headers`
  and the CSP plug don't cover. Runs as an endpoint plug (ahead of the router)
  so every surface — HTML, JSON, feeds, GraphQL, MCP — gets them uniformly.

    * `permissions-policy` — deny browser features the app never uses.
    * `cross-origin-opener-policy: same-origin` — isolate the browsing context
      from cross-origin popups. Safe here: OAuth uses full-page redirects.
    * `x-frame-options: DENY` — legacy clickjacking defence for old browsers
      (modern ones honour the CSP `frame-ancestors 'none'` directive instead).
    * `cross-origin-resource-policy: same-site` — restrict who may fetch our
      resources cross-origin. Set as a default here, but deliberately *removed*
      on the public data endpoints (CVE/OSV JSON, Atom/RSS feeds) which are
      meant to be consumed from anywhere; see `VarselWeb.Plugs.PublicResource`.
  """
  @behaviour Plug

  import Plug.Conn

  @headers [
    {"permissions-policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"},
    {"cross-origin-opener-policy", "same-origin"},
    {"x-frame-options", "DENY"},
    {"cross-origin-resource-policy", "same-site"}
  ]

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts), do: merge_resp_headers(conn, @headers)
end
