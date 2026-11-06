# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Comment.Changes.EmitMentions do
  @moduledoc """
  Emits `:users_mentioned` for the accounts a posted comment mentions.

  The action declares the signal with `emit ..., dynamic?: true`.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Accounts.User
  alias Varsel.Cases.Comment.Mentions
  alias Varsel.Cases.Signals

  @impl Change
  def change(changeset, _opts, context) do
    Ash.Changeset.after_action(changeset, fn changeset, comment ->
      emit(changeset, comment, Mentions.user_ids(comment.body), context.actor)
    end)
  end

  defp emit(_changeset, comment, [], _actor), do: {:ok, comment}

  defp emit(changeset, comment, user_ids, actor) do
    payload = %{case_id: comment.case_id, user_ids: user_ids, actor_id: actor_id(actor)}

    with :ok <- Ash.Signals.emit(changeset, Signals, :users_mentioned, payload) do
      {:ok, comment}
    end
  end

  defp actor_id(%User{id: id}), do: id
  defp actor_id(_actor), do: nil
end
