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

  @doc "The relationship tree `Varsel.Cases.Render.render_cna/2` needs to render a case."
  @spec render_loads() :: keyword()
  def render_loads, do: @render_loads

  @doc """
  Loads everything `Varsel.Cases.Render.render_cna/2` needs, under `actor` (the
  render-tree children share the case's read policy, so whoever may read the
  case may load them).
  """
  @spec load_render_tree(Case.t(), keyword()) :: Case.t()
  def load_render_tree(case_record, opts \\ []) do
    Ash.load!(case_record, @render_loads, actor: opts[:actor])
  end

  @doc """
  Per-package derivation results. `refresh: true` recomputes every package
  and stores the caches (the publish path); otherwise cached results are used
  and only cache misses are computed (the preview path).
  """
  @spec derivations(Case.t(), keyword()) :: %{Ash.UUID.t() => map()}
  def derivations(case_record, opts \\ []) do
    refresh? = Keyword.get(opts, :refresh, false)

    Map.new(case_record.affected_packages, fn package ->
      {package.id, derivation_for(package, refresh?)}
    end)
  end

  defp derivation_for(%{derivation_cache: cache}, false) when is_map(cache), do: cache

  defp derivation_for(package, _refresh?) do
    {:ok, derivation} = Derivation.derive(package)

    # The entry points that reach here — refresh_derivation, the publish
    # handoff, preview — are already policy-gated; writing the resulting
    # derivation cache is just their downstream side effect, not a separately
    # authorized user edit.
    package
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    |> Ash.Changeset.for_update(:store_derivation, %{derivation_cache: derivation}, authorize?: false)
    |> Ash.update!()

    derivation
  end

  @doc """
  Renders the case and wraps the container into a full CVE record. Pass `actor`
  so the render-tree load is authorized (the preview calculation and the publish
  handoff both have one); `refresh: true` recomputes derivations.
  """
  @spec render(Case.t(), keyword()) ::
          {:ok, %{result: Render.Result.t(), cve_json: map()}}
  def render(case_record, opts \\ []) do
    case_record = load_render_tree(case_record, opts)
    result = Render.render_cna(case_record, derivations(case_record, opts))

    {:ok, %{result: result, cve_json: cve_json(case_record, result)}}
  end

  # A placeholder used in `cveMetadata.cveId` before a real ID is assigned, so
  # the preview can still assemble and validate a complete record. The publish
  # path guards on an assigned CVE record first (see PublishToCveRecord), so a
  # placeholder never reaches a real MITRE push.
  @placeholder_cve_id "CVE-0000-0000"

  # The full record: as handed to CveRecord.request_publish/update once a CVE
  # ID is assigned, or with a placeholder ID for a pre-assignment preview.
  defp cve_json(case_record, result) do
    %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => case_record.cve_id || @placeholder_cve_id,
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
    Varsel.CVE.validate_cve_record!(cve_json)
  end

  @doc """
  The CNA container currently published on the case's CVE record, or nil when
  the case was never published. `providerMetadata.dateUpdated` is stripped —
  MITRE stamps it on every push, so it would be pure diff noise.

  Expects `:cve_record` to be loaded (the `:published_cna` calculation declares
  it); reached only through that calculation's authorized load path.
  """
  @spec published_cna(Case.t()) :: map() | nil
  def published_cna(case_record) do
    with %{cve_record: %{cve_json: cve_json}} when is_map(cve_json) <- case_record,
         %{} = cna <- get_in(cve_json, ["containers", "cna"]) do
      case cna do
        %{"providerMetadata" => %{} = provider} ->
          Map.put(cna, "providerMetadata", Map.delete(provider, "dateUpdated"))

        _no_provider_metadata ->
          cna
      end
    else
      _never_published -> nil
    end
  end

  @doc """
  Recomputes and stores the derivation cache of one package, loading its
  boundary facts under `actor`.
  """
  @spec refresh_package(AffectedPackage.t(), keyword()) :: map()
  def refresh_package(package, opts \\ []) do
    package = Ash.load!(package, [:channels, :version_events], actor: opts[:actor])
    derivation_for(package, true)
  end
end
