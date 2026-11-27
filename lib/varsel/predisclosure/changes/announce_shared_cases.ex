# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Predisclosure.Changes.AnnounceSharedCases do
  @moduledoc """
  Emits `:case_shared` for the cases a new list row makes visible: a case
  added to a list reaches every subscriber of the list, and a new subscriber
  gets every case the list already holds. An upsert that kept the existing
  row wrote nothing, so it emits nothing.

  The action declares the signal with `emit ..., dynamic?: true`.
  """

  use Ash.Resource.Change

  alias Varsel.Accounts.User
  alias Varsel.Cases.Signals
  alias Varsel.Predisclosure.ListMember
  alias Varsel.Predisclosure.ListSubscriber

  require Ash.Query

  @impl Ash.Resource.Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn
      _changeset, %{__metadata__: %{upsert_skipped: true}} = record ->
        {:ok, record}

      changeset, record ->
        opts = Ash.Context.to_opts(context)
        actor_id = actor_id(context.actor)

        payloads =
          record
          |> shared(opts)
          |> Enum.map(fn {case_id, user_ids} ->
            %{case_id: case_id, user_ids: user_ids, actor_id: actor_id}
          end)

        with :ok <- Ash.Signals.emit_many(changeset, Signals, :case_shared, payloads) do
          {:ok, record}
        end
    end)
  end

  defp shared(%ListMember{case_id: case_id, list_id: list_id}, opts) do
    user_ids =
      ListSubscriber
      |> Ash.Query.filter(list_id == ^list_id)
      |> Ash.read!(opts)
      |> Enum.map(& &1.user_id)

    if user_ids == [], do: [], else: [{case_id, user_ids}]
  end

  defp shared(%ListSubscriber{list_id: list_id, user_id: user_id}, opts) do
    ListMember
    |> Ash.Query.filter(list_id == ^list_id)
    |> Ash.read!(opts)
    |> Enum.map(&{&1.case_id, [user_id]})
  end

  defp actor_id(%User{id: id}), do: id
  defp actor_id(_actor), do: nil
end
