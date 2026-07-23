# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ApplyOauthUserInfo do
  @moduledoc """
  Copies the GitHub OAuth `user_info` payload onto the user's profile
  attributes (github_id, github_handle, name, email).
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    user_info = Ash.Changeset.get_argument(changeset, :user_info)

    changeset
    |> Ash.Changeset.force_change_attribute(:github_id, to_string(user_info["sub"]))
    |> Ash.Changeset.force_change_attribute(:github_handle, user_info["preferred_username"])
    |> Ash.Changeset.force_change_attribute(:name, user_info["name"])
    |> Ash.Changeset.force_change_attribute(:email, user_info["email"])
  end
end
