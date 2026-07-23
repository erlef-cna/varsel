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
      # Bootstrap check during the very first GitHub registration: there is no
      # privileged actor yet, and User reads are POC-or-self, so the count of
      # existing users must bypass authorization.
      # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
      if Ash.count!(Varsel.Accounts.User, authorize?: false) < 1 do
        Ash.Changeset.force_change_attribute(changeset, :role, :poc)
      else
        changeset
      end
    end)
  end
end
