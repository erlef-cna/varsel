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
  alias Varsel.Cases.CaseAssignment

  require Ash.Query

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
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    invites =
      Cases.list_case_invites_for_identity!(strategy, identity.username, authorize?: false)

    Enum.each(invites, &claim_invite(&1, identity))
  end

  defp claim_invite(invite, identity) do
    if !assigned?(invite, identity) do
      # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
      Cases.assign_case_user!(
        %{case_id: invite.case_id, user_id: identity.user_id, note: invite.note},
        authorize?: false
      )
    end

    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    Cases.withdraw_case_invite!(invite, authorize?: false)
  end

  # Checked rather than rescued: a unique violation would abort the transaction
  # the sign-in runs in.
  defp assigned?(invite, identity) do
    CaseAssignment
    |> Ash.Query.filter(case_id == ^invite.case_id and user_id == ^identity.user_id)
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    |> Ash.exists?(authorize?: false)
  end

  defp strategy_atom("github"), do: :github
  defp strategy_atom("hex"), do: :hex
  defp strategy_atom(_other), do: nil
end
