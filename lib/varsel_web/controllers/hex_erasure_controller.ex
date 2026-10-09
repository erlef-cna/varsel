# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexErasureController do
  use VarselWeb, :controller

  alias Varsel.Cases
  alias Varsel.CVE

  require Logger

  @doc "Takes hex.pm's notice that it erased an account it had named to us."
  def create(conn, params) do
    case parse(params) do
      {:ok, username, email} -> erase(conn, username, email)
      {:error, reason} -> refuse(conn, reason)
    end
  end

  defp erase(conn, username, email) do
    actor = Ash.PlugHelpers.get_actor(conn)

    with %Ash.BulkResult{status: :success} <-
           CVE.erase_hex_report_participants(username, email, actor: actor),
         %Ash.BulkResult{status: :success} <-
           Cases.erase_hex_case_invites(username, email, actor: actor) do
      send_resp(conn, :no_content, "")
    else
      # The errors can carry the erased person's details, so only their kinds are logged.
      %Ash.BulkResult{errors: errors} ->
        kinds = Enum.map_join(errors, ", ", &inspect(&1.__struct__))
        Logger.error("Could not apply a hex.pm erasure: #{kinds}")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "could not apply the erasure"})
    end
  end

  defp refuse(conn, reason) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: reason})
  end

  defp parse(%{"username" => username} = params) when is_binary(username) do
    cond do
      String.trim(username) == "" -> {:error, "username is required"}
      is_nil(params["email"]) -> {:ok, username, nil}
      is_binary(params["email"]) -> {:ok, username, params["email"]}
      true -> {:error, "email must be a string or null"}
    end
  end

  defp parse(_params), do: {:error, "username is required"}
end
