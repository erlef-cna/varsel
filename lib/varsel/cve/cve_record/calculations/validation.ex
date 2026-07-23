# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.CveRecord.Calculations.Validation do
  @moduledoc """
  The schema/cvelint/hex validation of a CVE record's stored `cve_json`.

  Records without a `cve_json` yet (reserved/draft/publishing) have nothing to
  validate and calculate to `nil`.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:cve_json]

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, fn
      %{cve_json: nil} -> nil
      %{cve_json: cve_json} -> Varsel.CVE.validate_cve_record!(cve_json)
    end)
  end
end
