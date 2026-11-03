# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Validation do
  @moduledoc """
  The validation of the case's rendered record — the validation slice of
  `:preview`, for callers that only want the verdict. The record of an
  upstream CVE gets only the schema check.

  Depends on `:preview` (which already renders and validates), so it inherits
  the same applied-state semantics and read-policy authorization.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:preview, :upstream_cve]

  @impl Calculation
  def calculate(records, _opts, _context), do: Enum.map(records, &validate/1)

  defp validate(%{upstream_cve: true, preview: preview}), do: Varsel.CVE.validate_cve_record_schema!(preview.cve_record)

  defp validate(%{preview: preview}), do: Varsel.CVE.validate_cve_record!(preview.cve_record)
end
