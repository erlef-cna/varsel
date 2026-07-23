# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Projection do
  @moduledoc """
  The case as it would look if every open proposal were accepted — the basis
  of the case page's Propose mode.

  `:set` proposals overwrite the field (values cast through the attribute's
  real Ash type; uncastable values are skipped), `:insert` proposals appear
  as phantom rows carrying the proposal's id, and `:delete` proposals mark
  their target row. Editing against the projection and diffing against it
  yields exactly the *new* proposals a change needs — untouched proposed
  values produce nothing, changed ones become counter-proposals via
  `set_proposals`.
  """

  alias Ash.Resource.Info
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.AffectedPackage.Preset
  alias Varsel.Cases.Case
  alias Varsel.Cases.Proposal
  alias Varsel.Cases.Proposal.Target

  @enforce_keys [:case, :phantom_ids, :deleted_ids, :set_proposals]
  defstruct [:case, :phantom_ids, :deleted_ids, :set_proposals]

  @type t :: %__MODULE__{
          case: Case.t(),
          phantom_ids: MapSet.t(Ash.UUID.t()),
          deleted_ids: MapSet.t(Ash.UUID.t()),
          set_proposals: %{{atom(), Ash.UUID.t() | nil, String.t()} => Proposal.t()}
        }

  @doc """
  Projects the case's open proposals onto it. The case must have `:proposals`
  and the full child tree loaded.
  """
  @spec project(Case.t()) :: t()
  def project(case_record) do
    open = Enum.filter(case_record.proposals, &(&1.state == :open))
    sets = Enum.filter(open, &(&1.operation == :set))
    inserts = Enum.filter(open, &(&1.operation == :insert))
    deletes = Enum.filter(open, &(&1.operation == :delete))

    projected =
      case_record
      |> apply_sets(sets)
      |> apply_inserts(inserts)

    %__MODULE__{
      case: projected,
      phantom_ids: MapSet.new(inserts, & &1.id),
      deleted_ids: MapSet.new(deletes, & &1.target_id),
      set_proposals: Map.new(sets, &{{&1.target, &1.target_id, &1.field_name}, &1})
    }
  end

  @doc "The open :set proposal a change to this field would counter, if any."
  @spec countered(t(), atom(), Ash.UUID.t() | nil, String.t()) :: Proposal.t() | nil
  def countered(%__MODULE__{set_proposals: set_proposals}, target, target_id, field_name) do
    Map.get(set_proposals, {target, target_id, field_name})
  end

  ## ------------------------------------------------------------------- sets

  defp apply_sets(case_record, sets) do
    Enum.reduce(sets, case_record, &apply_set/2)
  end

  defp apply_set(%{target: :case} = proposal, case_record) do
    set_field(case_record, Case, proposal)
  end

  defp apply_set(%{target: :affected_package} = proposal, case_record) do
    update_packages(case_record, fn package ->
      if package.id == proposal.target_id do
        set_field(package, AffectedPackage, proposal)
      else
        package
      end
    end)
  end

  defp apply_set(%{target: target} = proposal, case_record) when target in [:package_channel, :version_event] do
    {resource, key} =
      case target do
        :package_channel -> {Varsel.Cases.PackageChannel, :channels}
        :version_event -> {Varsel.Cases.VersionEvent, :version_events}
      end

    update_packages(case_record, fn package ->
      Map.put(package, key, set_row(Map.get(package, key), resource, proposal))
    end)
  end

  defp apply_set(%{target: target} = proposal, case_record) when target in [:reference, :credit] do
    key = if target == :reference, do: :references, else: :credits
    rows = set_row(Map.get(case_record, key), Target.resource(target), proposal)

    Map.put(case_record, key, rows)
  end

  # Weaknesses/impacts are insert/delete-only; no :set can target them.
  defp apply_set(_proposal, case_record), do: case_record

  defp set_row(rows, resource, proposal) do
    Enum.map(rows, fn row ->
      if row.id == proposal.target_id, do: set_field(row, resource, proposal), else: row
    end)
  end

  defp set_field(row, resource, proposal) do
    case cast_value(resource, proposal.field_name, proposal.proposed_value["value"]) do
      {:ok, field, value} -> Map.put(row, field, value)
      :error -> row
    end
  end

  ## ---------------------------------------------------------------- inserts

  defp apply_inserts(case_record, inserts) do
    Enum.reduce(inserts, case_record, &apply_insert/2)
  end

  defp apply_insert(%{target: :affected_package} = proposal, case_record) do
    phantom =
      proposal
      |> phantom_row(AffectedPackage, case_record.id)
      |> merge_preset_constants(proposal)
      |> Map.merge(%{channels: [], version_events: []})

    Map.update!(case_record, :affected_packages, &(&1 ++ [phantom]))
  end

  defp apply_insert(%{target: target} = proposal, case_record) when target in [:package_channel, :version_event] do
    key = if target == :package_channel, do: :channels, else: :version_events

    phantom =
      proposal
      |> phantom_row(Target.resource(target), case_record.id)
      |> Map.put(:affected_package_id, proposal.target_id)

    update_packages(case_record, fn package ->
      if package.id == proposal.target_id do
        Map.update!(package, key, &(&1 ++ [phantom]))
      else
        package
      end
    end)
  end

  defp apply_insert(%{target: :weakness} = proposal, case_record) do
    phantom =
      proposal
      |> phantom_row(Varsel.Cases.CaseWeakness, case_record.id)
      |> with_catalog(:weakness, Varsel.CWE.Weakness, :cwe_id)

    Map.update!(case_record, :weaknesses, &(&1 ++ [phantom]))
  end

  defp apply_insert(%{target: :impact} = proposal, case_record) do
    phantom =
      proposal
      |> phantom_row(Varsel.Cases.CaseImpact, case_record.id)
      |> with_catalog(:attack_pattern, Varsel.CAPEC.AttackPattern, :capec_id)

    Map.update!(case_record, :impacts, &(&1 ++ [phantom]))
  end

  defp apply_insert(%{target: target} = proposal, case_record) when target in [:reference, :credit] do
    key = if target == :reference, do: :references, else: :credits
    phantom = phantom_row(proposal, Target.resource(target), case_record.id)

    Map.update!(case_record, key, &(&1 ++ [phantom]))
  end

  defp apply_insert(_proposal, case_record), do: case_record

  # A preset insert payload carries no vendor/product itself; show the
  # constants the accepted proposal would stamp.
  defp merge_preset_constants(row, proposal) do
    payload = proposal.proposed_value["value"] || %{}

    case Preset.cast(payload["preset"] || payload[:preset]) do
      {:ok, preset} -> Map.merge(row, Preset.attributes(preset))
      :error -> row
    end
  end

  # A phantom row impersonates the row the accepted proposal would create; it
  # carries the proposal's id so the UI can tell it apart.
  defp phantom_row(proposal, resource, case_id) do
    base = struct(resource, id: proposal.id, case_id: case_id)

    Enum.reduce(proposal.proposed_value["value"] || %{}, base, fn {key, value}, row ->
      case cast_value(resource, key, value) do
        {:ok, field, cast} -> Map.put(row, field, cast)
        :error -> row
      end
    end)
  end

  defp with_catalog(row, key, catalog_resource, id_field) do
    catalog_row =
      case Ash.get(catalog_resource, Map.get(row, id_field)) do
        {:ok, found} ->
          found

        {:error, _} ->
          struct(catalog_resource, [
            {id_field, Map.get(row, id_field)},
            {:name, "(not in catalog)"}
          ])
      end

    Map.put(row, key, catalog_row)
  end

  ## ---------------------------------------------------------------- helpers

  defp update_packages(case_record, fun) do
    Map.update!(case_record, :affected_packages, fn packages -> Enum.map(packages, fun) end)
  end

  defp cast_value(resource, field_name, value) do
    with {:ok, field} <- existing_field(resource, field_name),
         %{} = attribute <- Info.attribute(resource, field),
         {:ok, cast} <- Ash.Type.cast_input(attribute.type, value, attribute.constraints) do
      {:ok, field, cast}
    else
      _uncastable -> :error
    end
  end

  defp existing_field(_resource, field) when is_atom(field), do: {:ok, field}

  defp existing_field(_resource, field) when is_binary(field) do
    {:ok, String.to_existing_atom(field)}
  rescue
    ArgumentError -> :error
  end
end
