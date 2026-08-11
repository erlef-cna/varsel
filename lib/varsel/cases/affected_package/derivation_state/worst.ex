# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.AffectedPackage.DerivationState.Worst do
  @moduledoc """
  A case's derivation state: whichever of its products most needs attention.

  Deriving runs case-wide, so one answer covers the case — and it has to be the
  worst one, since a single outdated product makes the record as a whole
  untrustworthy.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.Cases.AffectedPackage.DerivationState

  @impl Calculation
  def load(_query, _opts, _context), do: [:package_derivation_states]

  @impl Calculation
  def calculate(cases, _opts, _context) do
    Enum.map(cases, &DerivationState.worst(&1.package_derivation_states || []))
  end
end
