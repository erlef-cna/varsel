# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.UserInstallation.ForActor do
  @moduledoc """
  Answers which installations of the GitHub App the actor's own GitHub token
  reaches.

  The actor's rows answer when all of them are less than ten minutes old.
  Otherwise `Varsel.GitHub.App` asks GitHub with the actor's own token from
  `Varsel.GitHub.UserToken`, and GitHub's answer replaces the actor's rows.
  An actor without a GitHub identity reaches nothing, and no request goes
  out.
  """

  use Ash.Resource.ManualRead

  alias Varsel.Accounts.User
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Sync
  alias Varsel.GitHub.UserInstallation
  alias Varsel.GitHub.UserToken

  @lifetime to_timeout(minute: 10)

  @impl Ash.Resource.ManualRead
  def read(_query, _data_layer_query, _opts, %{actor: %User{} = actor} = context) do
    if UserToken.linked?(actor), do: cached(actor, Sync.opts(context)), else: {:ok, []}
  end

  def read(_query, _data_layer_query, _opts, _context), do: {:ok, []}

  defp cached(actor, opts) do
    case Ash.read(UserInstallation, opts) do
      {:ok, [_row | _rows] = rows} ->
        if Enum.all?(rows, &fresh?/1), do: {:ok, rows}, else: refresh(actor, rows, opts)

      {:ok, []} ->
        refresh(actor, [], opts)

      {:error, error} ->
        {:error, error}
    end
  end

  defp fresh?(%UserInstallation{fetched_at: fetched_at}),
    do: DateTime.diff(DateTime.utc_now(), fetched_at, :millisecond) < @lifetime

  defp refresh(actor, rows, opts) do
    with {:ok, token} <- UserToken.fetch(actor),
         {:ok, ids} <- App.user_installations(token),
         :ok <- forget(rows, opts) do
      store(Enum.uniq(ids), opts)
    else
      {:error, reason} when is_exception(reason) -> {:error, reason}
      {:error, reason} -> {:error, RequestFailed.exception(reason: reason)}
    end
  end

  defp forget(rows, opts) do
    Enum.reduce_while(rows, :ok, fn row, :ok ->
      case Ash.destroy(row, [action: :forget] ++ opts) do
        :ok -> {:cont, :ok}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  defp store(ids, opts) do
    fetched_at = DateTime.utc_now()

    Enum.reduce_while(ids, {:ok, []}, fn id, {:ok, stored} ->
      case Ash.create(
             UserInstallation,
             %{installation_id: id, fetched_at: fetched_at},
             [action: :store] ++ opts
           ) do
        {:ok, row} -> {:cont, {:ok, [row | stored]}}
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end
end
