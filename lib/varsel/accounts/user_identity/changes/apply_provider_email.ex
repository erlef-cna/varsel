# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ApplyProviderEmail do
  @moduledoc """
  Copies the email out of the OAuth `user_info` payload onto the identity row,
  so each linked provider keeps the address it reported.

  The address is recorded as a fact about the provider account, not as a
  verified address: it is what the user may later choose from as their primary
  email, and choosing it is a separate, deliberate act.
  """

  use Ash.Resource.Change

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    email =
      changeset
      |> Ash.Changeset.get_argument(:user_info)
      |> Kernel.||(%{})
      |> Map.get("email")

    Ash.Changeset.force_change_attribute(changeset, :email, email)
  end
end
