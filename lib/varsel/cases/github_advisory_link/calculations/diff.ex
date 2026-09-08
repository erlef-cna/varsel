# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryLink.Calculations.Diff do
  @moduledoc """
  The linked case against the stored advisory, as `Varsel.Cases.GitHubAdvisory.Diff`
  rows, loadable on the link.

  Loads the case with what the diff reads, as the actor loading the link, so
  it is as authorized as the link read itself.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.Cases.GitHubAdvisory.Diff
  alias Varsel.Cases.GitHubAdvisory.Export

  @impl Calculation
  def load(_query, _opts, _context), do: [:advisory, case: Export.load()]

  @impl Calculation
  def calculate(links, _opts, _context) do
    Enum.map(links, &Diff.rows(&1.case, &1.advisory))
  end
end
