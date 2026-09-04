# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ClaimCaseInvites do
  @moduledoc """
  Turns the invites naming a handle into real assignments once the provider
  vouches for it.

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
    identity.strategy
    |> strategy_atom()
    |> claim_for(identity)
  end

  defp claim_for(nil, _identity), do: :ok

  defp claim_for(strategy, identity) do
    invites =
      Cases.list_case_invites_for_identity!(strategy, identity.username, actor: Service.identity_claim())

    Enum.each(invites, &claim_invite(&1, identity))
  end

  defp claim_invite(invite, identity) do
    Cases.assign_case_user!(
      %{case_id: invite.case_id, user_id: identity.user_id, note: invite.note},
      actor: Service.identity_claim()
    )

    Cases.withdraw_case_invite!(invite, actor: Service.identity_claim())
  end

  defp strategy_atom("github"), do: :github
  defp strategy_atom("hex"), do: :hex
  defp strategy_atom(_other), do: nil
end
