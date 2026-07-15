# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI.Tools do
  @moduledoc """
  The research assistant's lookup tools, as plain generic actions (no data
  layer) exposed through the `Varsel.AI` domain's tool registry.

  ⚠️ Internal only — these must never appear in the MCP router's tool list
  or in GraphQL. `fetch_url` in particular would hand outside users a
  server-side open proxy (SSRF primitive); `Varsel.AI.WebFetch` blocks
  private targets as a second layer, but not being reachable is the first.
  """

  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.AI,
    authorizers: [Ash.Policy.Authorizer]

  alias Varsel.AI.WebFetch
  alias Varsel.CVE.HexPm

  actions do
    action :fetch_url, :map do
      description """
      Fetches a public http(s) page — advisory, changelog, commit/diff,
      release notes — and returns its textual content. HTML is reduced to
      plain text and long bodies are truncated.
      """

      argument :url, :string do
        allow_nil? false
        description "Absolute http(s) URL to fetch."
      end

      run fn input, _context -> WebFetch.fetch(input.arguments.url) end
    end

    action :hex_package_info, :map do
      description """
      Looks a package up on hex.pm: description, repository links, licenses,
      released versions, and retirements. Use it to verify package names and
      find the canonical repository URL.
      """

      argument :name, :string do
        allow_nil? false
        description "The hex.pm package name."
      end

      run fn input, _context -> HexPm.package_info(input.arguments.name) end
    end
  end

  policies do
    policy always() do
      authorize_if actor_present()
    end
  end
end
