# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.DerivedReferences do
  @moduledoc """
  The references the published record adds on its own — the `cna.erlef.org` /
  `osv.dev` self-links and the fix-commit links — as a loadable calculation.

  Like `Varsel.Cases.Case.Calculations.AffectedSummary`, it reads them off the
  case's own rendered `references[]` rather than rebuilding them, so what a
  client sees here is exactly what will ship and the derivation rules stay in
  one place (`Varsel.Cases.Case.Calculations.Preview`).

  Derived-ness is decided by URL: anything in the rendered list that no stored
  `Varsel.Cases.CaseReference` claims was added by the renderer. That also means
  a stored row whose URL a derived link would have produced is reported as
  stored, which matches how the render resolves the conflict.

  Each entry is a `Varsel.Cases.Case.DerivedReference`.
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.Cases.Case.Calculations.Preview
  alias Varsel.Cases.Case.DerivedReference

  @impl Calculation
  def load(_query, _opts, _context), do: [:preview, :references]

  # `load/3` asks for `:preview` and `Preview` always renders a `Result`, so the
  # match is total. Anything else — an `%Ash.NotLoaded{}` above all — is a bug
  # worth crashing on rather than quietly reporting no derived references.
  @impl Calculation
  def calculate(cases, _opts, _context) do
    Enum.map(cases, fn %{preview: %Preview.Result{cve_record: cve_record}, references: stored} ->
      stored_urls = MapSet.new(stored, & &1.url)

      cve_record
      |> get_in(["containers", "cna", "references"])
      |> List.wrap()
      |> Enum.reject(&MapSet.member?(stored_urls, &1["url"]))
      |> Enum.map(&%DerivedReference{url: &1["url"], tags: &1["tags"] || []})
    end)
  end
end
