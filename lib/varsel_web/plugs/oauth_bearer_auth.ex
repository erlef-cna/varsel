# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.OauthBearerAuth do
  @moduledoc """
  Authenticates OAuth 2.1 access tokens minted by `Varsel.Oauth2Server`.

  Runs after the other credential plugs (`VarselWeb.Plugs.ApiKeyAuth`,
  `load_from_bearer`/`set_actor`): when one of them already resolved an
  actor, the request passes through. Otherwise `BearerPlug` validates the
  bearer token as an OAuth access token, sets the actor, or replies 401
  with the `WWW-Authenticate` challenge that points OAuth/MCP clients at
  the protected-resource metadata for auto-discovery.

  The required `:scope` option names the scope a token must carry for
  this surface ("mcp" for the MCP endpoint, "gql" for GraphQL); a valid
  token without it gets a 403 `insufficient_scope` response (RFC 6750
  §3.1). API keys and session JWTs are the user's own credentials, not
  delegated grants, so they are exempt from scope checks.
  """
  @behaviour Plug

  import Plug.Conn

  alias AshAuthentication.Phoenix.Oauth2Server.BearerPlug

  @impl Plug
  def init(opts) do
    {scope, opts} = Keyword.pop!(opts, :scope)
    %{scope: scope, bearer: BearerPlug.init(opts)}
  end

  @impl Plug
  def call(conn, %{scope: scope, bearer: bearer}) do
    if Ash.PlugHelpers.get_actor(conn) do
      conn
    else
      conn
      |> BearerPlug.call(bearer)
      |> enforce_scope(scope)
    end
  end

  defp enforce_scope(%Plug.Conn{halted: true} = conn, _scope), do: conn

  defp enforce_scope(conn, scope) do
    granted =
      conn.assigns
      |> Map.get(:oauth_claims, %{})
      |> Map.get("scope", "")
      |> String.split(" ", trim: true)

    if scope in granted do
      conn
    else
      conn
      |> put_resp_header(
        "www-authenticate",
        ~s|Bearer error="insufficient_scope", scope="#{scope}"|
      )
      |> send_resp(403, "")
      |> halt()
    end
  end
end
