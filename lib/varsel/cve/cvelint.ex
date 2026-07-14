# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Cvelint do
  @moduledoc """
  Runs the `cvelint` binary (https://github.com/mprpic/cvelint) against a CVE
  record.

  cvelint only accepts `.json` files (no stdin), so the record is written to a
  short-lived temporary file named after its CVE ID. E007 (invalid version
  string) is ignored, matching the configuration used in the CNA records repo.

  The executable is expected on `$PATH` (provided by devenv); override with

      config :varsel, :cvelint_bin, "/path/to/cvelint"
  """

  @ignored_rules "E007"

  @doc """
  Lints a decoded CVE record map.

  Returns `:ok` or `{:error, [{message, json_path | nil}]}`.
  """
  @spec lint(map()) :: :ok | {:error, [{String.t(), String.t() | nil}]}
  def lint(cve_json) when is_map(cve_json) do
    # cvelint silently skips ("not a CVE v5 JSON record") anything without an
    # assignerShortName — reject upfront instead of pretending it was linted
    case get_in(cve_json, ["cveMetadata", "assignerShortName"]) do
      short_name when short_name in [nil, ""] ->
        {:error,
         [
           {"cveMetadata.assignerShortName is missing — cvelint skips records without it",
            "cveMetadata.assignerShortName"}
         ]}

      _ ->
        cve_id = get_in(cve_json, ["cveMetadata", "cveId"]) || "CVE-0000-0000"

        tmp_dir =
          Path.join(
            System.tmp_dir!(),
            "cvelint-#{System.unique_integer([:positive])}"
          )

        File.mkdir_p!(tmp_dir)
        path = Path.join(tmp_dir, "#{cve_id}.json")
        File.write!(path, Jason.encode!(cve_json))

        try do
          run(path)
        after
          File.rm_rf!(tmp_dir)
        end
    end
  end

  defp run(path) do
    bin = Application.get_env(:varsel, :cvelint_bin, "cvelint")

    # cvelint writes a progress indicator to stderr — discard it so stdout is
    # pure JSON. Erlang ports cannot silence stderr directly, hence the shell.
    args = [
      "-c",
      ~S(exec "$0" "$@" 2>/dev/null),
      bin,
      "-format",
      "json",
      "-ignore",
      @ignored_rules,
      path
    ]

    case System.cmd("/bin/sh", args) do
      {_out, 0} ->
        :ok

      {_out, status} when status in [126, 127] ->
        {:error, [{"cvelint executable not found (is it installed and on $PATH?)", nil}]}

      {out, _status} ->
        {:error, parse_errors(out)}
    end
  end

  defp parse_errors(out) do
    case Jason.decode(out) do
      {:ok, %{"results" => results}} when results != [] ->
        Enum.map(results, &parse_error/1)

      _ ->
        [{"cvelint failed: #{String.trim(out)}", nil}]
    end
  end

  defp parse_error(result) do
    message = "#{result["errorCode"]} (#{result["ruleName"]}): #{result["errorText"]}"
    path = if result["errorPath"] == "", do: nil, else: result["errorPath"]
    {message, path}
  end
end
