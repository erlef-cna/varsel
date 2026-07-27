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

  # The record's own id names the temp file, and the record is caller-supplied
  # at any authenticated privilege (the `validate_cve_record_*` tools). Anything
  # that is not a CVE ID — a path separator, `..`, an absolute path — would
  # steer `Path.join/2` out of the temp directory, so only this shape is used
  # as a filename and everything else falls back to the placeholder.
  @cve_id_shape ~r/^CVE-\d{4}-\d{4,19}$/i
  @placeholder_cve_id "CVE-0000-0000"

  @doc """
  Lints a decoded CVE record map.

  Returns `:ok` or `{:error, [{code | nil, message, json_path | nil}]}`.
  """
  # sobelow_skip ["Traversal.FileModule"]
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
        cve_id = filename_id(get_in(cve_json, ["cveMetadata", "cveId"]))

        tmp_dir =
          Path.join(
            System.tmp_dir!(),
            "cvelint-#{System.unique_integer([:positive])}"
          )

        File.mkdir_p!(tmp_dir)
        path = Path.join(tmp_dir, "#{cve_id}.json")
        File.write!(path, JSON.encode!(cve_json))

        try do
          run(path)
        after
          File.rm_rf!(tmp_dir)
        end
    end
  end

  # cvelint reads the record from the file, so the name only has to identify it
  # in an error message; a record whose id is missing or malformed still lints
  # under the placeholder, and the lint reports the bad id itself.
  defp filename_id(cve_id) when is_binary(cve_id) do
    if Regex.match?(@cve_id_shape, cve_id), do: cve_id, else: @placeholder_cve_id
  end

  defp filename_id(_not_a_string), do: @placeholder_cve_id

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
        {:error, [{nil, "cvelint executable not found (is it installed and on $PATH?)", nil}]}

      {out, _status} ->
        {:error, parse_errors(out)}
    end
  end

  defp parse_errors(out) do
    case JSON.decode(out) do
      {:ok, %{"results" => results}} when results != [] ->
        Enum.map(results, &parse_error/1)

      _ ->
        [{nil, "cvelint failed: #{String.trim(out)}", nil}]
    end
  end

  defp parse_error(result) do
    code = result["errorCode"]
    message = "#{code} (#{result["ruleName"]}): #{result["errorText"]}"
    path = if result["errorPath"] == "", do: nil, else: result["errorPath"]
    {code, message, path}
  end
end
