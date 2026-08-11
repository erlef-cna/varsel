# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.GrantAccess do
  @moduledoc """
  Behind `Varsel.Cases.Case`'s `:grant_access`: assigns the handle's owner when
  we already hold an identity for it, and invites them when we do not.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Cases

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Changeset.before_action(changeset, fn changeset ->
      case grant(changeset, context) do
        {:ok, _granted} -> changeset
        {:error, error} -> Changeset.add_error(changeset, error)
      end
    end)
  end

  defp grant(changeset, context) do
    strategy = Changeset.get_argument(changeset, :strategy)
    username = changeset |> Changeset.get_argument(:username) |> to_string() |> String.trim()
    case_id = changeset.data.id
    opts = Ash.Context.to_opts(context)

    case owner(strategy, username) do
      nil ->
        Cases.invite_to_case(
          %{case_id: case_id, strategy: strategy, username: username},
          opts
        )

      user_id ->
        Cases.assign_case_user(%{case_id: case_id, user_id: user_id}, opts)
    end
  end

  # Unauthorized because the answer is never reported as such — the caller sees
  # an assignment or an invite, neither of which says who else exists here.
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
