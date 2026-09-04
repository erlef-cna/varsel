# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.GrantAccess do
  @moduledoc """
  Behind `Varsel.Cases.Case`'s `:grant_access`. Assigns the owner of the handle
  when we hold an identity for it. Invites the handle when we do not. Leaves a
  person who is on the case as they are.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Cases
  alias Varsel.Cases.CaseInvite

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
      nil -> invite(changeset, case_id, strategy, username, opts)
      user_id -> Cases.assign_case_user(%{case_id: case_id, user_id: user_id}, opts)
    end
  end

  # The invite action confirms the handle at its provider before it writes the
  # row, so a repeat must stop before the action.
  defp invite(changeset, case_id, strategy, username, opts) do
    if invited?(case_id, strategy, username, opts) do
      {:ok, :invited}
    else
      Cases.invite_to_case(
        %{
          case_id: case_id,
          strategy: strategy,
          username: username,
          email: Changeset.get_argument(changeset, :email),
          skip_email: Changeset.get_argument(changeset, :skip_email)
        },
        opts
      )
    end
  end

  defp invited?(case_id, strategy, username, opts) do
    CaseInvite
    |> Ash.Query.filter(case_id == ^case_id and strategy == ^strategy and username == ^username)
    |> Ash.exists?(opts)
  end

  # The answer is never reported back: the caller sees an assignment or an
  # invite, neither of which says who else exists here.
  defp owner(strategy, username) do
    UserIdentity
    |> Ash.Query.filter(strategy == ^to_string(strategy) and username == ^username)
    |> Ash.Query.select([:user_id])
    |> Ash.read_one(actor: Varsel.Service.identity_claim())
    |> case do
      {:ok, %{user_id: user_id}} -> user_id
      _none -> nil
    end
  end
end
