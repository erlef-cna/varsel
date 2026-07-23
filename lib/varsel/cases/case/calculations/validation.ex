# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Validation do
  @moduledoc """
  The schema/cvelint/hex validation of the case's rendered record — the
  validation slice of `:preview`, for callers that only want the verdict.

  Depends on `:preview` (which already renders and validates), so it inherits
  the same applied-state semantics and read-policy authorization.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:preview]

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, &Varsel.CVE.validate_cve_record!(&1.preview.cve_record))
  end
end
