# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.PromoteFirstUserToPoc do
  @moduledoc """
  The very first user to ever log in becomes a POC, so the CNA always has
  someone who can manage roles. Only applies on insert (the upsert leaves
  existing users' roles untouched).
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Ash.Changeset.before_action(changeset, fn changeset ->
      if changeset.action_type == :create and
           Ash.count!(Varsel.Accounts.User, authorize?: false) == 0 do
        Ash.Changeset.force_change_attribute(changeset, :role, :poc)
      else
        changeset
      end
    end)
  end
end
