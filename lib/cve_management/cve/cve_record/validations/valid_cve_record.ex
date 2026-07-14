# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.CveRecord.Validations.ValidCveRecord do
  @moduledoc """
  Validates the changeset's `cve_json` via the CVE domain's
  `validate_cve_record/1` code interface (schema, cvelint, and hex.pm package
  checks — see `CveManagement.CVE.CveValidation`).

  Used on the actions that hand a record to MITRE (`request_publish` and
  `update`); records in earlier lifecycle states may hold invalid JSON.
  """

  use Ash.Resource.Validation

  @impl true
  def atomic(_changeset, _opts, _context) do
    # Only reached when the validation's `where` conditions match (Ash skips
    # it otherwise), i.e. on actions that must set `require_atomic? false`
    # anyway: the validators call external services.
    {:not_atomic, "CVE record validation calls external services and cannot run atomically"}
  end

  @impl true
  def validate(changeset, _opts, _context) do
    case Ash.Changeset.get_attribute(changeset, :cve_json) do
      # Leave missing JSON to the action's own presence checks. This also keeps
      # authorization dry-runs (e.g. `Ash.can?` when MCP filters visible tools)
      # from calling the external validators with no data.
      nil -> :ok
      cve_json -> validate_cve_json(cve_json)
    end
  end

  defp validate_cve_json(cve_json) do
    case CveManagement.CVE.validate_cve_record!(cve_json) do
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
