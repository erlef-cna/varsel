# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Mint do
  @moduledoc """
  The installation token of a stored `Varsel.GitHub.Installation`, shared
  by the `:token` and `:public_read_token` actions and the `:sync_all`
  schedule. Each caller decides who may get the token before it calls this
  module.

  The token stored on the row answers when it stays valid for at least five
  more minutes. Otherwise `Varsel.GitHub.App` mints a new one and the row
  stores it. The mint runs in a transaction that holds the row with
  `SELECT ... FOR UPDATE`, so concurrent callers on every node mint once:
  the callers that wait read the token that the first caller stored.
  """

  alias Varsel.GitHub
  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Installation

  @margin_seconds 300

  @doc """
  The token of the installation `installation_id`. `opts` are the options
  of `Varsel.GitHub.Sync.opts/1`. An installation that is not stored, or
  that the actor may not read, is `Ash.Error.Query.NotFound`.
  """
  @spec token(pos_integer(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def token(installation_id, opts) do
    with {:ok, installation} <- GitHub.get_installation(installation_id, [load: [:token]] ++ opts) do
      if valid?(installation), do: {:ok, installation.token}, else: renew(installation_id, opts)
    end
  end

  defp renew(installation_id, opts) do
    Installation
    |> Ash.DataLayer.transaction(
      fn -> locked_renew(installation_id, opts) end,
      nil,
      %{type: :custom, metadata: %{}},
      rollback_on_error?: true
    )
    |> case do
      {:ok, {:ok, token, notifications}} ->
        Ash.Notifier.notify(notifications)
        {:ok, token}

      {:ok, result} ->
        result

      error ->
        error
    end
  end

  defp locked_renew(installation_id, opts) do
    with {:ok, installation} <-
           GitHub.get_installation(
             installation_id,
             [load: [:token], query: [lock: :for_update]] ++ opts
           ) do
      if valid?(installation), do: {:ok, installation.token}, else: mint(installation, opts)
    end
  end

  defp mint(installation, opts) do
    case App.mint(installation.id) do
      {:ok, %{token: token, expires_at: expires_at}} ->
        with {:ok, _stored, notifications} <-
               GitHub.store_installation_token(
                 installation,
                 %{token: token, token_expires_at: expires_at},
                 [return_notifications?: true] ++ opts
               ) do
          {:ok, token, notifications}
        end

      {:error, reason} ->
        {:error, RequestFailed.exception(reason: reason)}
    end
  end

  defp valid?(%Installation{token: token, token_expires_at: %DateTime{} = expires_at}) when is_binary(token),
    do: DateTime.diff(expires_at, DateTime.utc_now()) >= @margin_seconds

  defp valid?(_installation), do: false
end
