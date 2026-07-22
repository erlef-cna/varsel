# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.CvssScore do
  @moduledoc """
  The case's CVSS v4.0 base score, read off the already-scored
  `Varsel.Types.CVSS` struct on `cvss_v4` (the `:cvss` library scores the
  vector once, at cast time — this calculation never re-scores). `nil` when
  the case has no CVSS vector yet.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation

  @impl Calculation
  def load(_query, _opts, _context), do: [:cvss_v4]

  @impl Calculation
  def calculate(records, _opts, _context) do
    Enum.map(records, fn
      %{cvss_v4: %Varsel.Types.CVSS{score: score}} -> score
      _unscored -> nil
    end)
  end
end
