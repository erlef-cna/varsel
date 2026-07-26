# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ApplyHexUserInfo do
  @moduledoc """
  Copies the Hex.pm OAuth `user_info` payload onto the user's profile.

  Only the display name and (when the account has none yet) the notification email
  are taken. Hex.pm has no equivalent of `github_handle`, and the hex username
  lives on the identity row as its `uid` rather than being denormalized here.
  """

  use Ash.Resource.Change

  alias Varsel.Accounts.User.Changes.SeedNotificationEmail

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    user_info = Ash.Changeset.get_argument(changeset, :user_info)

    changeset
    |> Ash.Changeset.force_change_attribute(:name, user_info["name"])
    |> SeedNotificationEmail.seed(user_info["email"])
  end
end
