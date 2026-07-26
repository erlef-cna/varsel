# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ApplyProviderFields do
  @moduledoc """
  Copies the email and username out of the OAuth `user_info` payload onto the
  identity row, so each linked provider keeps what it reported.

  Both are facts about the provider account rather than verified claims: the
  address is what a user may later choose as their notification email, and
  choosing it is a separate, deliberate act.

  Assent normalizes the handle to `preferred_username`; the raw GitHub and
  Hex.pm keys are accepted as well so the payload works either way.
  """

  use Ash.Resource.Change

  @username_keys ~w(preferred_username login username)

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    user_info = Ash.Changeset.get_argument(changeset, :user_info) || %{}

    changeset
    |> Ash.Changeset.force_change_attribute(:email, user_info["email"])
    |> Ash.Changeset.force_change_attribute(:username, username(user_info))
  end

  defp username(user_info), do: Enum.find_value(@username_keys, &user_info[&1])
end
