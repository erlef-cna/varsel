# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.HexServiceAuth do
  @moduledoc """
  Admits hex.pm's package-report intake, and nothing else.

  hex.pm submits on a reporter's behalf rather than as them, so the credential
  proves which system is calling rather than which person: a short-lived ES256
  token verified by `Varsel.HexIntake.ServiceToken` against a pinned key set.

  The request stays actor-less. Everything past this plug runs as no one, so
  the route it guards is the whole of the authorization story and the action
  behind it must not be reachable any other way.
  """
  @behaviour Plug

  import Plug.Conn

  alias Varsel.HexIntake.ServiceToken

  require Logger

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    with {:ok, token} <- bearer(conn),
         {:ok, _claims} <- ServiceToken.verify(token, audience()) do
      conn
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

  defp audience do
    :varsel
    |> Application.get_env(:hex_intake, [])
    |> Keyword.get(:audience, "")
  end

  defp refuse(conn, reason) do
    Logger.warning("Rejected a hex.pm report submission: #{reason}")

    conn
    |> put_resp_content_type("application/json")
    |> put_resp_header("www-authenticate", ~s(Bearer error="invalid_token"))
    |> send_resp(:unauthorized, JSON.encode!(%{error: "invalid_token"}))
    |> halt()
  end
end
