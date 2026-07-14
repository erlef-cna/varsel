# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Changes.SupersedeCompeting do
  @moduledoc """
  After a proposal is accepted, sweeps competing open proposals to
  `:superseded` (in the same transaction):

  * `:set` — other open proposals for the same `(target, target_id,
    field_name)`. Counter-proposals need no special handling: they share the
    key with their parent, so accepting either supersedes the other.
  * `:delete` — every open proposal on the deleted row (its fields can no
    longer be set or re-deleted). Pending inserts *under* the deleted row are
    swept by `Varsel.Cases.Changes.SupersedeOrphanedProposals` on the destroy.
  * `:insert` — supersedes nothing.
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Proposal

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn _changeset, proposal ->
      proposal
      |> competing_query()
      |> sweep(proposal, context.actor)

      {:ok, proposal}
    end)
  end

  defp competing_query(%{operation: :set} = proposal) do
    Proposal
    |> Ash.Query.filter(
      case_id == ^proposal.case_id and state == :open and id != ^proposal.id and
        target == ^proposal.target and field_name == ^proposal.field_name
    )
    |> filter_target_id(proposal.target_id)
  end

  defp competing_query(%{operation: :delete} = proposal) do
    Proposal
    |> Ash.Query.filter(
      case_id == ^proposal.case_id and state == :open and id != ^proposal.id and
        target == ^proposal.target
    )
    |> filter_target_id(proposal.target_id)
  end

  defp competing_query(%{operation: :insert}), do: nil

  defp filter_target_id(query, nil), do: Ash.Query.filter(query, is_nil(target_id))
  defp filter_target_id(query, target_id), do: Ash.Query.filter(query, target_id == ^target_id)

  defp sweep(nil, _proposal, _actor), do: :ok

  defp sweep(query, proposal, actor) do
    Ash.bulk_update!(
      query,
      :supersede,
      %{resolution_note: "superseded by accepted proposal #{proposal.id}"},
      actor: actor,
      authorize?: false,
      strategy: :stream,
      return_errors?: true
    )
  end
end
