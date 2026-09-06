# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ClaimCaseCredits do
  @moduledoc """
  Links the credits naming a handle to the account once the provider vouches
  for it. The credit keeps the name and organization it was given.

  Runs on `:upsert`, which is the one path both a first sign-in and a later
  provider link take.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Cases
  alias Varsel.Service

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    Changeset.after_action(changeset, fn _changeset, identity ->
      claim(identity)
      {:ok, identity}
    end)
  end

  defp claim(%{username: nil}), do: :ok

  defp claim(identity) do
    credits =
      Cases.list_case_credits_for_identity!(identity.strategy, to_string(identity.username),
        actor: Service.identity_claim()
      )

    Enum.each(
      credits,
      &Cases.claim_case_credit!(&1, %{user_id: identity.user_id}, actor: Service.identity_claim())
    )
  end
end
