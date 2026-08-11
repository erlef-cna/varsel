# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.HexReportController do
  use VarselWeb, :controller

  alias Varsel.CVE

  require Logger

  @doc """
  Takes a package report forwarded by hex.pm.

  The sender treats any response other than 201 as an outage and does not
  retry, so a rejection here costs the reporter their submission. Rejections
  are logged with what was wrong: a schema drift on either side should be
  loud rather than a quietly rising failure count.
  """
  def create(conn, params) do
    case parse(params) do
      {:ok, attrs} -> submit(conn, attrs)
      {:error, reason} -> refuse(conn, reason)
    end
  end

  defp submit(conn, attrs) do
    case CVE.submit_hex_vulnerability_report(attrs, authorize?: true) do
      {:ok, report} ->
        url = url(~p"/reports")

        conn
        |> put_resp_header("location", url)
        |> put_status(:created)
        |> json(%{
          id: report.id,
          url: url,
          sign_in_url: url(~p"/auth/user/hex?return_to=#{~p"/reports"}")
        })

      {:error, error} ->
        Logger.error("Could not store a hex.pm report: #{Exception.message(error)}")

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "could not store the report"})
    end
  end

  defp refuse(conn, reason) do
    Logger.warning("Rejected a malformed hex.pm report: #{reason}")

    conn
    |> put_status(:bad_request)
    |> json(%{error: reason})
  end

  # The payload is issue #94's contract, which hexpm/hexpm#1823 sends verbatim.
  # It is kept whole in report_json: the package string in particular is stored
  # as hex.pm spells it rather than parsed into a purl, which is a judgement a
  # human makes when the case is opened.
  defp parse(%{"summary" => summary, "description" => description, "package" => package} = params)
       when is_binary(summary) and is_binary(description) and is_binary(package) do
    with {:ok, reporter} <- person(params["reporter"], :reporter),
         {:ok, maintainers} <- people(params["maintainers"]) do
      {:ok,
       %{
         summary: String.slice(summary, 0, 2_000),
         report_json: %{
           "summary" => summary,
           "description" => description,
           "package" => package
         },
         participants: [reporter | maintainers]
       }}
    end
  end

  defp parse(_params), do: {:error, "summary, description and package are required"}

  defp people(nil), do: {:ok, []}

  defp people(maintainers) when is_list(maintainers) do
    Enum.reduce_while(maintainers, {:ok, []}, fn maintainer, {:ok, acc} ->
      case person(maintainer, :maintainer) do
        {:ok, participant} -> {:cont, {:ok, acc ++ [participant]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp people(_maintainers), do: {:error, "maintainers must be a list"}

  defp person(%{"username" => username} = person, role) when is_binary(username) and username != "" do
    {:ok,
     %{
       role: role,
       strategy: :hex,
       username: username,
       name: person["name"],
       email: person["email"]
     }}
  end

  defp person(_person, role), do: {:error, "#{role} must carry a username"}
end
