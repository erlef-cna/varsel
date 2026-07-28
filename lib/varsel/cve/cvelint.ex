# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Cvelint do
  @moduledoc """
  Runs the `cvelint` binary (https://github.com/mprpic/cvelint) against a CVE
  record.

  E007 (invalid version string) is ignored, matching the configuration used in
  the CNA records repo.

  The executable is expected on `$PATH` (provided by devenv); override with

      config :varsel, :cvelint_bin, "/path/to/cvelint"
  """

  @ignored_rules "E007"

  @doc """
  Lints a decoded CVE record map.

  Returns `:ok` or `{:error, [{code | nil, message, json_path | nil}]}`.
  """
  @spec lint(map()) ::
          :ok | {:error, [{String.t() | nil, String.t(), String.t() | nil}]}
  def lint(cve_json) when is_map(cve_json) do
    # cvelint silently skips ("not a CVE v5 JSON record") anything without an
    # assignerShortName — reject upfront instead of pretending it was linted
    case get_in(cve_json, ["cveMetadata", "assignerShortName"]) do
      short_name when short_name in [nil, ""] ->
        {:error,
         [
           {nil, "cveMetadata.assignerShortName is missing — cvelint skips records without it",
            "cveMetadata.assignerShortName"}
         ]}

      _ ->
        cve_json |> JSON.encode!() |> run()
    end
  end

  defp run(input) do
    bin = Application.get_env(:varsel, :cvelint_bin, "cvelint")

    if System.find_executable(bin) do
      lint_via(bin, input)
    else
      {:error, [{nil, "cvelint executable not found (is it installed and on $PATH?)", nil}]}
    end
  end

  defp lint_via(bin, input) do
    [bin, "-format", "json", "-ignore", @ignored_rules, "-"]
    |> Exile.stream(input: [input], ignore_epipe: true)
    |> Stream.reject(&match?({:exit, _status}, &1))
    |> Varsel.JSON.decode!()
    |> to_errors()
  rescue
    JSON.DecodeError -> {:error, [{nil, "cvelint produced no readable report", nil}]}
  end

  defp to_errors(%{"results" => results}) when results != [] do
    {:error, Enum.map(results, &parse_error/1)}
  end

  defp to_errors(_no_results), do: :ok

  defp parse_error(result) do
    code = result["errorCode"]
    message = "#{code} (#{result["ruleName"]}): #{result["errorText"]}"
    path = if result["errorPath"] == "", do: nil, else: result["errorPath"]
    {code, message, path}
  end
end
