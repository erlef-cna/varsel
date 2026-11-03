# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Validations.ValidCveRecord do
  @moduledoc """
  Validates the changeset's `cve_json` via the CVE domain's
  `validate_cve_record/1` code interface (schema, cvelint, hex.pm package, and
  EEF policy checks), or `validate_cve_record_schema/1` for an upstream CVE
  (see `Varsel.CVE.CveValidation`).

  Used on the actions that publish a record (`request_publish`, `update` and
  `publish_enrichment`); records in earlier lifecycle states may hold invalid
  JSON.
  """

  use Ash.Resource.Validation

  alias Ash.Resource.Validation

  @impl Validation
  def atomic(_changeset, _opts, _context) do
    # Only reached when the validation's `where` conditions match (Ash skips
    # it otherwise), i.e. on actions that must set `require_atomic? false`
    # anyway: the validators call external services.
    {:not_atomic, "CVE record validation calls external services and cannot run atomically"}
  end

  @impl Validation
  def validate(changeset, _opts, _context) do
    case Ash.Changeset.get_attribute(changeset, :cve_json) do
      # Leave missing JSON to the action's own presence checks. This also keeps
      # authorization dry-runs (e.g. `Ash.can?` when MCP filters visible tools)
      # from calling the external validators with no data.
      nil -> :ok
      %Ash.NotLoaded{} -> :ok
      cve_json -> validate_cve_json(cve_json, changeset.data.upstream)
    end
  end

  # The row's flag decides, not the record's assignerOrgId, so a record of
  # this CNA's own CVE always gets every check.
  defp validate_cve_json(cve_json, upstream?) do
    result =
      if upstream?,
        do: Varsel.CVE.validate_cve_record_schema!(cve_json),
        else: Varsel.CVE.validate_cve_record!(cve_json)

    case result do
      %{valid: true} ->
        :ok

      %{errors: errors} ->
        message = Enum.map_join(errors, "\n", &format_error/1)
        {:error, field: :cve_json, message: "CVE record is not valid:\n" <> message}
    end
  end

  defp format_error(error) do
    location = if error.path, do: " (at #{error.path})", else: ""
    "[#{error.source}] #{error.message}#{location}"
  end
end
