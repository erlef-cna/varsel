# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.HexServiceAuth do
  @moduledoc """
  Authenticates hex.pm's package-report intake.

  A verified request runs as `Varsel.Service.hexpm_intake/0`. Nothing else
  builds that actor, so holding it means a signature checked out here.
  """
  @behaviour Plug

  use VarselWeb, :verified_routes

  import Plug.Conn

  alias Varsel.HexIntake.ServiceToken
  alias Varsel.Service

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    with {:ok, token} <- bearer(conn),
         {:ok, _claims} <- ServiceToken.verify(token, audience()) do
      Ash.PlugHelpers.set_actor(conn, Service.hexpm_intake())
    else
      {:error, reason} -> refuse(conn, reason)
    end
  end

  defp bearer(conn) do
    case get_req_header(conn, "authorization") do
      ["Bearer " <> token] -> {:ok, String.trim(token)}
      _other -> {:error, :missing_token}
    end
  end

  # The address hex.pm was told to post to. Built from the route rather than
  # the request, so the caller's Host header cannot decide which audience its
  # own token has to match.
  defp audience, do: url(~p"/api/hex/reports")

  defp refuse(conn, _reason) do
    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("www-authenticate", ~s(Bearer error="invalid_token"))
    |> send_resp(:unauthorized, JSON.encode!(%{error: "invalid_token"}))
    |> halt()
  end
end
