# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.SeverityBucket do
  @moduledoc """
  The case's severity rating (`:none`/`:low`/`:medium`/`:high`/`:critical`),
  or `nil` when it has no CVSS vector yet.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  require Ash.Expr

  @impl Calculation
  def load(_query, _opts, _context), do: [:cvss_v4]

  @impl Calculation
  def expression(_opts, _context) do
    Ash.Expr.expr(fragment("?->>'severity'", cvss_v4))
  end

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, fn
      %{cvss_v4: %Varsel.Types.CVSS{severity: severity}} -> severity
      _unscored -> nil
    end)
  end
end
