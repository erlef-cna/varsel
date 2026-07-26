# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ApplyOauthUserInfo do
  @moduledoc """
  Copies the GitHub OAuth `user_info` payload onto the user's profile
  attributes (github_id, github_handle, name, email).

  The email is only *seeded*: it is written when the account has none yet, so
  the address a user later picks as their primary (see `:set_primary_email`)
  survives every subsequent sign-in. Each provider's own reported address is
  kept on its identity row regardless.
  """

  use Ash.Resource.Change

  alias Varsel.Accounts.User.Changes.SeedPrimaryEmail

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    user_info = Ash.Changeset.get_argument(changeset, :user_info)

    changeset
    |> Ash.Changeset.force_change_attribute(:github_id, to_string(user_info["sub"]))
    |> Ash.Changeset.force_change_attribute(:github_handle, user_info["preferred_username"])
    |> Ash.Changeset.force_change_attribute(:name, user_info["name"])
    |> SeedPrimaryEmail.seed(user_info["email"])
  end
end
