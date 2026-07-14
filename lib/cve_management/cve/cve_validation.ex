# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveValidation.Error do
  @moduledoc """
  A single validation finding for a CVE record.
  """

  use Ash.Resource, data_layer: :embedded, extensions: [AshGraphql.Resource]

  graphql do
    type :cve_validation_error
  end

  attributes do
    attribute :source, CveManagement.CVE.CveValidation.Source do
      description "Which validator produced this finding."
      allow_nil? false
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

defmodule CveManagement.CVE.CveValidation.Result do
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

    attribute :errors, {:array, CveManagement.CVE.CveValidation.Error} do
      allow_nil? false
      default []
      public? true
    end
  end
end

defmodule CveManagement.CVE.CveValidation do
  @moduledoc """
  Stateless validation service for CVE records, exposed as an Ash resource so
  the checks are callable as actions (and via MCP).

  Validators:

  - `:schema` — the official CVE record JSON schema (vendored, see
    `CveManagement.CVE.CveSchema`)
  - `:cvelint` — the `cvelint` binary (see `CveManagement.CVE.Cvelint`)
  - `:hex` — every `pkg:hex/...` package URL in the affected entries must
    reference an existing package on hex.pm (see `CveManagement.CVE.HexPm`)
  """

  use Ash.Resource, otp_app: :cve_management, domain: CveManagement.CVE

  alias CveManagement.CVE.Cvelint
  alias CveManagement.CVE.CveSchema
  alias CveManagement.CVE.CveValidation.Error
  alias CveManagement.CVE.CveValidation.Result
  alias CveManagement.CVE.HexPm

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
  end

  defp errors(cve_json) do
    schema_errors(cve_json) ++ cvelint_errors(cve_json) ++ hex_errors(cve_json)
  end

  defp result(errors), do: struct(Result, %{valid: errors == [], errors: errors})

  defp schema_errors(cve_json) do
    case CveSchema.validate(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {message, path} ->
          error(:schema, message, path)
        end)
    end
  end

  defp cvelint_errors(cve_json) do
    case Cvelint.lint(cve_json) do
      :ok ->
        []

      {:error, errors} ->
        Enum.map(errors, fn {message, path} ->
          error(:cvelint, message, path)
        end)
    end
  end

  defp hex_errors(cve_json) do
    cve_json
    |> HexPm.hex_package_names()
    |> Enum.flat_map(fn name ->
      case HexPm.package_exists?(name) do
        {:ok, true} -> []
        {:ok, false} -> [error(:hex, "package #{inspect(name)} does not exist on hex.pm")]
        {:error, reason} -> [error(:hex, reason)]
      end
    end)
  end

  defp error(source, message, path \\ nil) do
    struct(Error, %{source: source, message: message, path: path})
  end
end
