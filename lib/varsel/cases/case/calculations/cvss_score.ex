# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.CvssScore do
  @moduledoc """
  The case's CVSS v4.0 base score for the GENERAL scenario, or `nil` when it
  has no GENERAL metric yet.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  require Ash.Expr

  @impl Calculation
  def load(_query, _opts, _context), do: [general_metric: [:cvss_v4]]

  @impl Calculation
  def expression(_opts, _context) do
    Ash.Expr.expr(fragment("(?->>'score')::float", general_metric.cvss_v4))
  end

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, fn
      %{general_metric: %{cvss_v4: %Varsel.Types.CVSS{score: score}}} -> score
      _unscored -> nil
    end)
  end
end
