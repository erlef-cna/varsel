# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.CaseCredit.Changes.ResolveCreditedUser do
  @moduledoc """
  Confirms a credit's handles at their providers, links the credit to the
  account holding one of them, and completes the credit from that account:
  the name and organization the person asked to be credited as, and the
  handles their other providers know them by.

  `mode: :fill` writes only what the credit leaves blank, so what a caller
  gave stands, and a handle the row already carries is not asked about again.
  A credit with no account and no name takes the name the provider lists for
  the handle. `mode: :overwrite` asks about every handle again and replaces
  the name and organization with the account's current preference, or the
  name with the one the provider now lists when no account holds a handle.
  """

  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Resource.Change
  alias Varsel.Accounts.HandleLookup
  alias Varsel.Accounts.User
  alias Varsel.Accounts.UserIdentity
  alias Varsel.Cases.CaseInvite.Strategy
  alias Varsel.Service

  require Ash.Query

  @modes [:fill, :overwrite]

  @impl Change
  def init(opts) do
    if opts[:mode] in @modes,
      do: {:ok, opts},
      else: {:error, "mode must be one of #{inspect(@modes)}"}
  end

  @impl Change
  def change(changeset, opts, _context) do
    Changeset.before_action(changeset, fn changeset ->
      case confirm_handles(changeset, opts[:mode]) do
        {:ok, %{handles: handles, names: names, user_id: user_id}} ->
          changeset
          |> Changeset.change_attribute(:handles, handles)
          |> link_user(user_id)
          |> complete(opts[:mode], names)

        {:error, message} ->
          Changeset.add_error(changeset, field: :handles, message: message)
      end
    end)
  end

  ## --------------------------------------------------------------- handles

  defp confirm_handles(changeset, mode) do
    known =
      if mode == :fill,
        do: changeset.data |> Map.get(:handles) |> List.wrap() |> Enum.map(&plain/1),
        else: []

    changeset
    |> Changeset.get_attribute(:handles)
    |> List.wrap()
    |> Enum.map(&plain/1)
    |> Enum.reject(&(&1.username == ""))
    |> Enum.uniq_by(& &1.strategy)
    |> Enum.reduce_while({:ok, %{handles: [], names: [], user_id: nil}}, fn handle, {:ok, acc} ->
      case confirm(handle, known) do
        {:ok, handle, name, user_id} ->
          {:cont,
           {:ok,
            %{
              handles: [handle | acc.handles],
              names: acc.names ++ List.wrap(name),
              user_id: acc.user_id || user_id
            }}}

        {:error, message} ->
          {:halt, {:error, message}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, %{acc | handles: Enum.reverse(acc.handles)}}
      error -> error
    end
  end

  defp confirm(handle, known) do
    cond do
      stored = Enum.find(known, &same_handle?(&1, handle)) ->
        {:ok, stored, nil, nil}

      identity = identity_for(handle) ->
        {:ok, %{handle | username: to_string(identity.username)}, nil, identity.user_id}

      true ->
        case HandleLookup.confirm(handle.strategy, handle.username) do
          {:ok, %{username: canonical, name: name}} ->
            {:ok, %{handle | username: canonical}, name, nil}

          {:error, message} ->
            {:error, "#{handle.username} #{message}"}
        end
    end
  end

  ## ------------------------------------------------------------------ user

  defp identity_for(%{strategy: strategy, username: username}) do
    strategy = to_string(strategy)

    UserIdentity
    |> Ash.Query.filter(strategy == ^strategy and username == ^username)
    |> Ash.Query.select([:user_id, :username])
    |> Ash.read_one!(actor: Service.identity_claim())
  end

  ## -------------------------------------------------------------- complete

  defp plain(%{strategy: strategy, username: username}) do
    %{strategy: strategy, username: username |> to_string() |> String.trim()}
  end

  defp same_handle?(left, right) do
    left.strategy == right.strategy and
      String.downcase(left.username) == String.downcase(right.username)
  end

  defp link_user(changeset, user_id) do
    case Changeset.get_attribute(changeset, :user_id) do
      nil -> Changeset.change_attribute(changeset, :user_id, user_id)
      _user_id -> changeset
    end
  end

  defp complete(changeset, mode, provider_names) do
    case Changeset.get_attribute(changeset, :user_id) do
      nil -> complete_from_provider(changeset, mode, provider_names)
      user_id -> complete_from_user(changeset, mode, user_id)
    end
  end

  defp complete_from_provider(changeset, :overwrite, []) do
    Changeset.add_error(changeset,
      field: :handles,
      message: "names no account here and no handle whose provider lists a name"
    )
  end

  defp complete_from_provider(changeset, :overwrite, [name | _rest]) do
    Changeset.change_attribute(changeset, :name, name)
  end

  defp complete_from_provider(changeset, :fill, names) do
    put_if_blank(changeset, :name, List.first(names))
  end

  defp complete_from_user(changeset, mode, user_id) do
    user =
      User
      |> Ash.Query.filter(id == ^user_id)
      |> Ash.Query.load([
        :credit_display_name,
        :credit_organization,
        identities: [:strategy, :username]
      ])
      |> Ash.read_one!(actor: Service.identity_claim())

    changeset
    |> put_from_user(mode, user)
    |> merge_handles(user)
  end

  defp put_from_user(changeset, :overwrite, user) do
    changeset
    |> Changeset.change_attribute(:name, user.credit_display_name)
    |> Changeset.change_attribute(:organization, user.credit_organization)
  end

  defp put_from_user(changeset, :fill, user) do
    changeset
    |> put_if_blank(:name, user.credit_display_name)
    |> put_if_blank(:organization, user.credit_organization)
  end

  defp put_if_blank(changeset, _attribute, nil), do: changeset

  defp put_if_blank(changeset, attribute, value) do
    if blank?(Changeset.get_attribute(changeset, attribute)),
      do: Changeset.change_attribute(changeset, attribute, value),
      else: changeset
  end

  # Only the providers a credit can name; the mock login is not one of them.
  defp merge_handles(changeset, user) do
    given = changeset |> Changeset.get_attribute(:handles) |> List.wrap() |> Enum.map(&plain/1)

    from_identities =
      for identity <- user.identities,
          not is_nil(identity.username),
          {:ok, strategy} <- [Strategy.match(identity.strategy)],
          not Enum.any?(given, &(&1.strategy == strategy)) do
        %{strategy: strategy, username: to_string(identity.username)}
      end

    Changeset.change_attribute(changeset, :handles, given ++ from_identities)
  end

  defp blank?(nil), do: true
  defp blank?(value), do: String.trim(value) == ""
end
