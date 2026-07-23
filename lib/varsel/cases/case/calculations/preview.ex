# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Calculations.Preview do
  @moduledoc """
  Renders the case to its CNA container without publishing: the container, the
  full CVE record, which override escape hatches fired, and the conditions that
  would block publishing (plus a validation summary once a CVE ID is assigned).

  Loading this calculation is the only preview entry point, so authorization is
  the case read policy itself — you can only `load(:preview)` on a case you were
  allowed to read. Uses cached per-package derivations (`refresh_derivation`
  recomputes them).
  """

  use Ash.Resource.Calculation

  alias Ash.Resource.Calculation
  alias Varsel.Cases.Publication

  @impl Calculation
  def load(_query, _opts, _context), do: Publication.render_loads()

  @impl Calculation
  def calculate(records, _opts, context), do: Enum.map(records, &preview(&1, context.actor))

  defp preview(case_record, actor) do
    {:ok, %{result: result, cve_json: cve_json}} = Publication.render(case_record, actor: actor)
    validation = cve_json && Publication.validate(cve_json)

    %{
      "cna" => result.cna,
      "cve_json" => cve_json,
      "blockers" => result.blockers,
      "overrides_applied" => result.overrides_applied,
      "validation" => validation && Map.take(validation, [:valid, :errors])
    }
  end
end
