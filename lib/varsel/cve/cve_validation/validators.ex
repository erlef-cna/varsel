# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Validators do
  @moduledoc """
  The CVE record validators themselves, behind the actions of
  `Varsel.CVE.CveValidation`.

  Each entry point takes the decoded record and returns a list of
  `Varsel.CVE.CveValidation.Error` structs, empty when the record passes.
  """

  alias Varsel.CVE.Cvelint
  alias Varsel.CVE.CveSchema
  alias Varsel.CVE.CveValidation.Error
  alias Varsel.CVE.CveValidation.Result
  alias Varsel.HexPm

  def errors(cve_json) do
    schema_errors(cve_json) ++
      cvelint_errors(cve_json) ++
      hex_errors(cve_json) ++
      eef_errors(cve_json)
  end

  def result(errors), do: struct(Result, %{valid: errors == [], errors: errors})

  def schema_errors(cve_json) do
    case CveSchema.validate(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {message, path} ->
          error(:schema, nil, message, path)
        end)
    end
  end

  def cvelint_errors(cve_json) do
    case Cvelint.lint(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {code, message, path} ->
          error(:cvelint, code, message, path)
        end)
    end
  end

  def hex_errors(cve_json) do
    cve_json
    |> hex_package_names()
    |> Enum.flat_map(fn name ->
      case HexPm.package_exists?(name) do
        {:ok, true} ->
          []

        {:ok, false} ->
          [error(:hex, "HEX001", "package #{inspect(name)} does not exist on hex.pm")]

        {:error, reason} ->
          [error(:hex, nil, reason)]
      end
    end)
  end

  # The placeholder id a preview carries until a real CVE ID is assigned
  # (see Varsel.Cases.Render).
  @placeholder_cve_id "CVE-0000-0000"

  # EEF/CNA policy checks beyond the CVE schema, which treats these as optional.
  def eef_errors(cve_json) do
    cna = get_in(cve_json, ["containers", "cna"]) || %{}

    title_error =
      if blank?(cna["title"]),
        do: [error(:eef, "EEF001", "title is missing", "containers.cna.title")],
        else: []

    cvss_error =
      if has_cvss_v4?(cna["metrics"]),
        do: [],
        else: [error(:eef, "EEF002", "CVSS v4 vector is missing", "containers.cna.metrics")]

    cve_id = get_in(cve_json, ["cveMetadata", "cveId"])

    cve_id_error =
      if blank?(cve_id) or cve_id == @placeholder_cve_id,
        do: [error(:eef, "EEF003", "no CVE ID assigned", "cveMetadata.cveId")],
        else: []

    cwe_error =
      if present?(cna["problemTypes"]),
        do: [],
        else: [error(:eef, "EEF004", "no CWE weakness recorded", "containers.cna.problemTypes")]

    capec_error =
      if present?(cna["impacts"]),
        do: [],
        else: [
          error(:eef, "EEF005", "no CAPEC attack pattern recorded", "containers.cna.impacts")
        ]

    title_error ++ cvss_error ++ cve_id_error ++ cwe_error ++ capec_error ++ semver_errors(cna)
  end

  # "semver"-typed version boundaries must parse as SemVer, or be one of the
  # sentinel values the schema allows in their place ("0" for an open-ended
  # introduced boundary, "*" for an open-ended upper bound). The schema and
  # cvelint accept these fields as opaque strings.
  defp semver_errors(cna) do
    cna
    |> Map.get("affected", [])
    |> List.wrap()
    |> Enum.with_index()
    |> Enum.flat_map(fn {affected, affected_index} ->
      affected
      |> Map.get("versions", [])
      |> List.wrap()
      |> Enum.with_index()
      |> Enum.filter(fn {version_entry, _index} -> version_entry["versionType"] == "semver" end)
      |> Enum.flat_map(fn {version_entry, version_index} ->
        path = "containers.cna.affected[#{affected_index}].versions[#{version_index}]"

        [
          semver_error(version_entry["version"], "#{path}.version"),
          semver_error(version_entry["lessThan"], "#{path}.lessThan"),
          semver_error(version_entry["lessThanOrEqual"], "#{path}.lessThanOrEqual")
          | semver_change_errors(version_entry["changes"], path)
        ]
      end)
      |> Enum.reject(&is_nil/1)
    end)
  end

  defp semver_change_errors(changes, path) do
    changes
    |> List.wrap()
    |> Enum.with_index()
    |> Enum.map(fn {change, change_index} ->
      semver_error(change["at"], "#{path}.changes[#{change_index}].at")
    end)
  end

  defp semver_error(value, _path) when value in [nil, "0", "*"], do: nil

  defp semver_error(value, path) do
    case Version.parse(value) do
      {:ok, _version} ->
        nil

      :error ->
        error(:eef, "EEF006", "#{inspect(value)} is not a valid SemVer version", path)
    end
  end

  defp present?(list) when is_list(list), do: list != []
  defp present?(_value), do: false

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_value), do: false

  defp has_cvss_v4?(metrics) when is_list(metrics), do: Enum.any?(metrics, &Map.has_key?(&1, "cvssV4_0"))

  defp has_cvss_v4?(_metrics), do: false

  defp error(source, code, message, path \\ nil) do
    struct(Error, %{source: source, code: code, message: message, path: path})
  end

  # The `pkg:hex/...` package names in a record's affected entries. Namespaced
  # purls (`pkg:hex/acme/foo`, private organization packages) are skipped —
  # their existence cannot be verified against the public repository — as are
  # unparsable package URLs, which the schema/lint validators flag.
  defp hex_package_names(cve_json) when is_map(cve_json) do
    cve_json
    |> get_in(["containers", "cna", "affected"])
    |> List.wrap()
    |> Enum.flat_map(fn affected ->
      with %{"packageURL" => purl_string} <- affected,
           {:ok, %Purl{type: "hex", namespace: [], name: name}} <- Purl.new(purl_string) do
        [name]
      else
        _ -> []
      end
    end)
    |> Enum.uniq()
  end
end
