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
    Ash.Changeset.after_action(changeset, fn _changeset, record ->
      sweep(record, context)
      {:ok, record}
    end)
  end

  defp sweep(record, context) do
    Proposal
    |> Ash.Query.filter(state == :open and target_id == ^record.id)
    |> Varsel.Cases.supersede_case_proposal!(
      %{resolution_note: "the targeted row was deleted"},
      actor: context.actor,
      authorize?: false,
      bulk_options: [strategy: :stream, return_errors?: true]
    )
  end
end
