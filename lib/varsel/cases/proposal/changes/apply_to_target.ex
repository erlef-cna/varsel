# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Changes.ApplyToTarget do
  @moduledoc """
  Applies an accepted proposal to its target inside the accept transaction.

  Dispatches on `{operation, target}` to the target resource's internal
  `apply_proposal` / `apply_proposal_insert` / `apply_proposal_delete` action,
  executed with the *accepting* user as actor — the paper trail on the target
  attributes the write to the approver, while proposer provenance stays on the
  proposal row.

  Runs as a `before_action` hook (inside the transaction) so a failing apply
  rolls back the state transition, and so an `:insert`'s created row id can be
  recorded on the proposal as `applied_target_id`.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Proposal.Target

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      proposal = changeset.data
      actor = context.actor

      case apply_to_target(proposal, actor) do
        {:ok, nil} ->
          changeset

        {:ok, %{id: applied_id}} ->
          Ash.Changeset.force_change_attribute(changeset, :applied_target_id, applied_id)

        {:error, :stale_target} ->
          Ash.Changeset.add_error(changeset,
            field: :target_id,
            message: "the targeted row no longer exists; decline this proposal instead"
          )

        {:error, error} ->
          Ash.Changeset.add_error(changeset, error)
      end
    end)
  end

  defp apply_to_target(%{operation: :set, target: :case} = proposal, actor) do
    case_record = Ash.get!(Varsel.Cases.Case, proposal.case_id, authorize?: false)

    case_record
    |> Ash.Changeset.for_update(:apply_proposal, apply_arguments(proposal), actor: actor)
    |> Ash.update()
    |> discard_result()
  end

  defp apply_to_target(%{operation: :set} = proposal, actor) do
    with {:ok, row} <- fetch_target_row(proposal) do
      row
      |> Ash.Changeset.for_update(:apply_proposal, apply_arguments(proposal), actor: actor)
      |> Ash.update()
      |> discard_result()
    end
  end

  defp apply_to_target(%{operation: :insert} = proposal, actor) do
    resource = Target.resource(proposal.target)
    payload = proposal.proposed_value["value"]

    params =
      payload
      |> Map.put("case_id", proposal.case_id)
      |> put_parent_key(proposal)
      |> Map.put("proposal_id", proposal.id)

    resource
    |> Ash.Changeset.for_create(:apply_proposal_insert, params, actor: actor)
    |> Ash.create()
  end

  defp apply_to_target(%{operation: :delete} = proposal, actor) do
    with {:ok, row} <- fetch_target_row(proposal) do
      case row
           |> Ash.Changeset.for_destroy(:apply_proposal_delete, %{proposal_id: proposal.id}, actor: actor)
           |> Ash.destroy() do
        :ok -> {:ok, nil}
        {:error, error} -> {:error, error}
      end
    end
  end

  defp apply_arguments(proposal) do
    %{
      field: proposal.field_name,
      value: proposal.proposed_value["value"],
      proposal_id: proposal.id
    }
  end

  defp put_parent_key(params, proposal) do
    case {Target.parent_key(proposal.target), proposal.target_id} do
      {:case_id, _} -> params
      {_key, nil} -> params
      {key, parent_id} -> Map.put(params, to_string(key), parent_id)
    end
  end

  defp fetch_target_row(proposal) do
    case Ash.get(Target.resource(proposal.target), proposal.target_id, authorize?: false) do
      {:ok, row} -> {:ok, row}
      {:error, _} -> {:error, :stale_target}
    end
  end

  defp discard_result({:ok, _record}), do: {:ok, nil}
  defp discard_result({:error, error}), do: {:error, error}
end
