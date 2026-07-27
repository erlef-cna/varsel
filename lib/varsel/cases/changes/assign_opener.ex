# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Changes.AssignOpener do
  @moduledoc """
  Fills the `:open` action's `assignments` argument with the acting user, so
  the managed relationship creates their assignment alongside the case.

  Whoever opens a case is working it, and for a supporter the assignment is
  what grants access at all — without it they would open a case and lose
  sight of it. A case opened without an actor (seeds, tooling) has nobody to
  assign and is left alone.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, %{actor: %{id: user_id}}) do
    Ash.Changeset.set_argument(changeset, :assignments, [
      %{user_id: user_id, note: "Opened the case"}
    ])
  end

  def change(changeset, _opts, _context), do: changeset
end
