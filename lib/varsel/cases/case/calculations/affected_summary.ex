# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.AffectedSummary do
  @moduledoc """
  The "This issue affects …" sentence the published record appends to the case
  description, as a loadable calculation.

  It reads the sentence off the case's own rendered `affected[]` — the same
  preview the record publishes — so what a client sees here is exactly what will
  ship. Clients need it to know NOT to write the sentence themselves; see
  `Varsel.Cases.Description.AffectedSummary`.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.Cases.Case.Calculations.Preview
  alias Varsel.Cases.Description.AffectedSummary

  @impl Calculation
  def load(_query, _opts, _context), do: [:preview]

  # `load/3` asks for `:preview` and `Preview` always renders a `Result`, so the
  # match is total. Anything else — an `%Ash.NotLoaded{}` above all — is a bug
  # worth crashing on rather than quietly summarizing nothing.
  @impl Calculation
  def calculate(cases, _opts, _context) do
    Enum.map(cases, fn %{preview: %Preview.Result{cve_record: cve_record}} ->
      cve_record
      |> get_in(["containers", "cna", "affected"])
      |> List.wrap()
      |> AffectedSummary.summarize()
    end)
  end
end
