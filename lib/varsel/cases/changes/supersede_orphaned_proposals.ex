# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Changes.SupersedeOrphanedProposals do
  @moduledoc """
  Attached to every child-resource destroy action: sweeps open proposals whose
  target row is being deleted to `:superseded`, so the proposal queue never
  holds dangling entries.

  Covers proposals that `:set`/`:delete` the destroyed row itself and pending
  `:insert` proposals whose *parent* is the destroyed row (e.g. version-event
  inserts under a destroyed package). The accept-time existence check on
  `Varsel.Cases.Proposal` remains the correctness backstop for anything that
  bypasses this (there is no FK on the polymorphic `target_id`).
  """

  use Ash.Resource.Change

  alias Varsel.Cases.Proposal

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    # On apply_proposal_delete the destroy is driven by a proposal that is
    # still :open in the database until its accept commits — it is being
    # resolved, not orphaned. Sweeping it would bump its version mid-accept
    # and fail the outer update's optimistic lock.
    driving_proposal_id = Ash.Changeset.get_argument(changeset, :proposal_id)

    Ash.Changeset.after_action(changeset, fn _changeset, record ->
      sweep(record, driving_proposal_id, context)
      {:ok, record}
    end)
  end

  @stamp %{private: %{proposal_sweep?: true}}

  defp sweep(record, driving_proposal_id, context) do
    opts =
      context
      |> Ash.Context.to_opts()
      |> Keyword.update(:context, @stamp, &Ash.Helpers.deep_merge_maps(&1, @stamp))

    Proposal
    |> Ash.Query.filter(state == :open and target_id == ^record.id)
    |> exclude_driving_proposal(driving_proposal_id)
    |> Varsel.Cases.supersede_case_proposal!(
      %{resolution_note: "the targeted row was deleted"},
      Keyword.put(opts, :bulk_options, strategy: :stream, return_errors?: true)
    )
  end

  defp exclude_driving_proposal(query, nil), do: query

  defp exclude_driving_proposal(query, proposal_id) do
    Ash.Query.filter(query, id != ^proposal_id)
  end
end
