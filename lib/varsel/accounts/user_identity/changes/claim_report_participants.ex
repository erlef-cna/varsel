# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.UserIdentity.Changes.ClaimReportParticipants do
  @moduledoc """
  Points the participants naming a handle at the account that just proved it
  owns it.

  Runs on `:upsert`, which is the one path both a first sign-in and a later
  provider link take. Unlike an invite, the row stays: it is the record of who
  an intake named, and the case assignment it turns into is made when a POC
  opens the case.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.CVE

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
    participants =
      CVE.list_report_participants_for_identity!(strategy, identity.username, authorize?: false)

    Enum.each(participants, fn participant ->
      # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
      CVE.link_report_participant_user!(participant, %{user_id: identity.user_id}, authorize?: false)
    end)
  end

  defp strategy_atom("github"), do: :github
  defp strategy_atom("hex"), do: :hex
  defp strategy_atom(_other), do: nil
end
