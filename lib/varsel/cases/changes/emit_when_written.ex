# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Changes.EmitWhenWritten do
  @moduledoc """
  Emits a `Varsel.Cases.Signals` signal for the row an upsert wrote, with the
  acting user as `actor_id`. An upsert that kept the existing row wrote
  nothing, so it emits nothing.

  `actor_field` names a record field to take `actor_id` from instead, for a
  row a service writes on behalf of the user who acted elsewhere.

  The action declares the signal with `emit ..., dynamic?: true`.
  """

  use Ash.Resource.Change

  alias Ash.Resource.Change
  alias Varsel.Accounts.User
  alias Varsel.Cases.Signals

  @impl Change
  def init(opts) do
    if is_atom(opts[:signal]) and is_list(opts[:fields]) and is_atom(opts[:actor_field]) do
      {:ok, opts}
    else
      {:error, "requires a `signal` and the record `fields` it takes, and `actor_field` must be an atom when set"}
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
          |> Map.put(:actor_id, actor_id(record, opts[:actor_field], context.actor))

        with :ok <- Ash.Signals.emit(changeset, Signals, opts[:signal], payload) do
          {:ok, record}
        end
    end)
  end

  defp actor_id(_record, nil, %User{id: id}), do: id
  defp actor_id(_record, nil, _actor), do: nil
  defp actor_id(record, field, _actor), do: Map.fetch!(record, field)
end
