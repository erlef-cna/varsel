# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Publication do
  @moduledoc """
  The shared render entry point behind previews and publishing: loads a case's
  render tree, obtains per-package derivations (cached for previews, freshly
  computed for publishing), renders the CNA container, and assembles/validates
  the full CVE record.
  """

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Cases.Derivation
  alias Varsel.Cases.Render

  @render_loads [
    :cve_id,
    :references,
    :credits,
    affected_packages: [:channels, :version_events],
    weaknesses: [:weakness],
    impacts: [:attack_pattern]
  ]

  @doc "Loads everything `Varsel.Cases.Render.render_cna/2` needs."
  @spec load_render_tree(Case.t()) :: Case.t()
  def load_render_tree(case_record) do
    Ash.load!(case_record, @render_loads, authorize?: false)
  end

  @doc """
  Per-package derivation results. `refresh: true` recomputes every package
  and stores the caches (the publish path); otherwise cached results are used
  and only cache misses are computed (the preview path).
  """
  @spec derivations(Case.t(), refresh: boolean()) :: %{Ash.UUID.t() => map()}
  def derivations(case_record, opts \\ []) do
    refresh? = Keyword.get(opts, :refresh, false)

    Map.new(case_record.affected_packages, fn package ->
      {package.id, derivation_for(package, refresh?)}
    end)
  end

  defp derivation_for(%{derivation_cache: cache}, false) when is_map(cache), do: cache

  defp derivation_for(package, _refresh?) do
    {:ok, derivation} = Derivation.derive(package)

    package
    |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: derivation}, authorize?: false)
    |> Ash.update!()

    derivation
  end

  @doc "Renders the case and wraps the container into a full CVE record."
  @spec render(Case.t(), refresh: boolean()) ::
          {:ok, %{result: Render.Result.t(), cve_json: map() | nil}}
  def render(case_record, opts \\ []) do
    case_record = load_render_tree(case_record)
    result = Render.render_cna(case_record, derivations(case_record, opts))

    {:ok, %{result: result, cve_json: cve_json(case_record, result)}}
  end

  # The full record as handed to CveRecord.request_publish/update. Only
  # assemblable once a CVE ID is assigned.
  defp cve_json(%{cve_id: nil}, _result), do: nil

  defp cve_json(case_record, result) do
    %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => case_record.cve_id,
        "assignerOrgId" => Application.fetch_env!(:varsel, :cna_org_id),
        "assignerShortName" => Application.get_env(:varsel, :cna_short_name, "EEF"),
        "state" => "PUBLISHED"
      },
      "containers" => %{"cna" => result.cna}
    }
  end

  @doc "Runs the full CveValidation suite over an assembled record."
  @spec validate(map()) :: Varsel.CVE.CveValidation.Result.t()
  def validate(cve_json) do
    Varsel.CVE.validate_cve_record!(cve_json, authorize?: false)
  end

  @doc "Marks every package's derivation cache stale so the next preview recomputes."
  @spec invalidate_derivations(Case.t()) :: :ok
  def invalidate_derivations(case_record) do
    case_record = Ash.load!(case_record, [:affected_packages], authorize?: false)

    Enum.each(case_record.affected_packages, fn package ->
      package
      |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: nil}, authorize?: false)
      |> Ash.update!()
    end)
  end

  @doc "Recomputes and stores the derivation cache of one package."
  @spec refresh_package(AffectedPackage.t()) :: map()
  def refresh_package(package) do
    package = Ash.load!(package, [:channels, :version_events], authorize?: false)
    derivation_for(package, true)
  end
end
