# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveValidation.Error do
  @moduledoc """
  A single validation finding for a CVE record.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :cve_validation_error
  end

  attributes do
    attribute :source, Varsel.CVE.CveValidation.Source do
      description "Which validator produced this finding."
      allow_nil? false
      public? true
    end

    attribute :code, :string do
      description ~s{Stable finding code, e.g. "E017" (cvelint) or "EEF002" (policy). Nil for uncoded findings.}
      allow_nil? true
      public? true
    end

    attribute :path, :string do
      description "JSON path of the offending element, when known."
      allow_nil? true
      public? true
    end

    attribute :message, :string do
      allow_nil? false
      public? true
    end
  end
end

defmodule Varsel.CVE.CveValidation.Result do
  @moduledoc """
  Aggregated result of validating a CVE record.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :cve_validation_result
  end

  attributes do
    attribute :valid, :boolean do
      allow_nil? false
      public? true
    end

    attribute :errors, {:array, Varsel.CVE.CveValidation.Error} do
      allow_nil? false
      default []
      public? true
    end
  end
end

defmodule Varsel.CVE.CveValidation do
  @moduledoc """
  Stateless validation service for CVE records, exposed as an Ash resource so
  the checks are callable as actions (and via MCP).

  Validators:

  - `:schema` — the official CVE record JSON schema (vendored, see
    `Varsel.CVE.CveSchema`)
  - `:cvelint` — the `cvelint` binary (see `Varsel.CVE.Cvelint`)
  - `:hex` — every `pkg:hex/...` package URL in the affected entries must
    reference an existing package on hex.pm (see `Varsel.HexPm`)
  """

  # AshGraphql.Resource is required even though this resource exposes no type
  # of its own: ash_graphql (>= 1.10) only builds a domain's `action` query
  # fields for resources that carry the extension. The generic actions here
  # are exposed as queries in Varsel.CVE, so the extension must be present.
  use Ash.Resource,
    otp_app: :varsel,
    domain: Varsel.CVE,
    extensions: [AshGraphql.Resource]

  alias Varsel.CVE.Cvelint
  alias Varsel.CVE.CveSchema
  alias Varsel.CVE.CveValidation.Error
  alias Varsel.CVE.CveValidation.Result
  alias Varsel.HexPm

  graphql do
    # This resource has no GraphQL type of its own; it only exposes generic
    # `action` queries (whose return types, Result/Error, are the real types).
    generate_object? false
  end

  resource do
    require_primary_key? false
  end

  actions do
    action :validate, Result do
      description "Runs all CVE record validators (schema, cvelint, hex.pm packages)."
      argument :cve_json, :map, allow_nil?: false

      run fn input, _context ->
        {:ok, result(errors(input.arguments.cve_json))}
      end
    end

    action :validate_schema, Result do
      description "Validates a CVE record against the official CVE JSON schema."
      argument :cve_json, :map, allow_nil?: false

      run fn input, _context ->
        {:ok, result(schema_errors(input.arguments.cve_json))}
      end
    end

    action :validate_cvelint, Result do
      description "Lints a CVE record with cvelint."
      argument :cve_json, :map, allow_nil?: false

      run fn input, _context ->
        {:ok, result(cvelint_errors(input.arguments.cve_json))}
      end
    end

    action :validate_hex_packages, Result do
      description "Checks that all pkg:hex package URLs reference existing hex.pm packages."
      argument :cve_json, :map, allow_nil?: false

      run fn input, _context ->
        {:ok, result(hex_errors(input.arguments.cve_json))}
      end
    end

    action :validate_eef, Result do
      description "Checks EEF/CNA policy requirements beyond the CVE schema (a title and a CVSS v4 metric)."
      argument :cve_json, :map, allow_nil?: false

      run fn input, _context ->
        {:ok, result(eef_errors(input.arguments.cve_json))}
      end
    end
  end

  defp errors(cve_json) do
    schema_errors(cve_json) ++
      cvelint_errors(cve_json) ++
      hex_errors(cve_json) ++
      eef_errors(cve_json)
  end

  defp result(errors), do: struct(Result, %{valid: errors == [], errors: errors})

  defp schema_errors(cve_json) do
    case CveSchema.validate(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {message, path} ->
          error(:schema, nil, message, path)
        end)
    end
  end

  defp cvelint_errors(cve_json) do
    case Cvelint.lint(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {code, message, path} ->
          error(:cvelint, code, message, path)
        end)
    end
  end

  defp hex_errors(cve_json) do
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
  defp eef_errors(cve_json) do
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

    title_error ++ cvss_error ++ cve_id_error ++ cwe_error ++ capec_error
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
