# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Changes.EmitWhenWritten do
  @moduledoc """
  Emits a `Varsel.Cases.Signals` signal for the row an upsert wrote, with the
  acting user as `actor_id`. An upsert that kept the existing row wrote
  nothing, so it emits nothing.

  The action declares the signal with `emit ..., dynamic?: true`.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Accounts.User
  alias Varsel.Cases.Signals

  @impl Change
  def init(opts) do
    if is_atom(opts[:signal]) and is_list(opts[:fields]) do
      {:ok, opts}
    else
      {:error, "requires a `signal` and the record `fields` it takes"}
    end
  end

  @impl Change
  def change(changeset, opts, context) do
    Ash.Changeset.after_action(changeset, fn
      _changeset, %{__metadata__: %{upsert_skipped: true}} = record ->
        {:ok, record}

      changeset, record ->
        payload =
          record
          |> Map.take(opts[:fields])
          |> Map.put(:actor_id, actor_id(context.actor))

        with :ok <- Ash.Signals.emit(changeset, Signals, opts[:signal], payload) do
          {:ok, record}
        end
    end)
  end

  defp actor_id(%User{id: id}), do: id
  defp actor_id(_actor), do: nil
end
