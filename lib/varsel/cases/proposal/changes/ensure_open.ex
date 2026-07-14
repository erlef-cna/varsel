# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Proposal.Changes.EnsureOpen do
  @moduledoc """
  Stale-write guard for proposal resolution: combined with
  `get_and_lock_for_update()` (declared before this change), the row is
  re-read under a row lock inside the transaction and must still be `:open` —
  two concurrent accepts cannot both apply, and a stale in-memory struct
  cannot resurrect a resolved proposal.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      case changeset.data.state do
        :open ->
          changeset

        state ->
          Ash.Changeset.add_error(changeset,
            field: :state,
            message: "the proposal was already resolved (%{state})",
            vars: [state: state]
          )
      end
    end)
  end
end
