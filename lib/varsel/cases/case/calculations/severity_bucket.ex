# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.SeverityBucket do
  @moduledoc """
  The case's severity chip bucket (`:none`/`:low`/`:medium`/`:high`/`:critical`),
  derived from the CVSS score via `VarselWeb.CoreComponents.severity_bucket/1`
  — the same bucketing the severity chip component renders with. `nil` when
  the case has no CVSS vector yet (the chip's distinct "no score" state, not
  `:none`).
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:cvss_v4]

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, fn
      %{cvss_v4: %Varsel.Types.CVSS{score: score}} ->
        VarselWeb.CoreComponents.severity_bucket(score)

      _unscored ->
        nil
    end)
  end
end
