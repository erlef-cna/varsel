# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.User.Changes.ApplyProviderProfile do
  @moduledoc """
  Copies an OAuth `user_info` payload onto the user's profile.

  Provider-agnostic, because nothing provider-specific reaches the user any
  more: the handle each provider knows someone by stays on its own identity
  row and surfaces through the `:github_username` and `:hex_username`
  calculations. That leaves the display name and the notification address.

  The address is only *seeded*: it is written when the account has none yet, so
  the one a user later picks (see `:set_notification_email`) survives every
  subsequent sign-in.
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
