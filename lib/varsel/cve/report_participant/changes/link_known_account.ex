# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.ReportParticipant.Changes.LinkKnownAccount do
  @moduledoc """
  Points a participant at the account holding its handle, if one already does.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts.UserIdentity

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, _context) do
    strategy = Changeset.get_attribute(changeset, :strategy)
    username = changeset |> Changeset.get_attribute(:username) |> to_string()

    case owner(strategy, username) do
      nil -> changeset
      user_id -> Changeset.force_change_attribute(changeset, :user_id, user_id)
    end
  end

  # Unauthorized because the answer is never reported as such: the caller is a
  # sending system that learns nothing about who exists here.
  defp owner(strategy, username) do
    UserIdentity
    |> Ash.Query.filter(strategy == ^to_string(strategy) and username == ^username)
    |> Ash.Query.select([:user_id])
    # credo:disable-for-next-line AshCredo.Check.Warning.AuthorizeFalse
    |> Ash.read_one(authorize?: false)
    |> case do
      {:ok, %{user_id: user_id}} -> user_id
      _none -> nil
    end
  end
end
