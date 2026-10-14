# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.Installation.Mint do
  @moduledoc """
  The installation token of a known `Varsel.GitHub.Installation`, shared by
  the `:token` and `:public_read_token` actions. Each action decides who may
  get the token before it calls this module.

  The token stored on the row answers when it stays valid for at least five
  more minutes. Otherwise `Varsel.GitHub.App` mints a new one and the row
  stores it. A `:global` lock per installation on the local node makes
  concurrent callers mint once: the callers that wait read the token that
  the first caller stored.
  """

  alias Varsel.GitHub.App
  alias Varsel.GitHub.Errors.RequestFailed
  alias Varsel.GitHub.Installation

  @margin_seconds 300

  @doc """
  The token of the installation `installation_id`. `opts` are the options
  of `Varsel.GitHub.Sync.opts/1`. An installation that no lookup stored is
  `Ash.Error.Query.NotFound`.
  """
  @spec token(pos_integer(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def token(installation_id, opts) do
    case Ash.get(Installation, installation_id, opts) do
      {:ok, installation} ->
        if valid?(installation),
          do: {:ok, installation.token},
          else: locked_renew(installation_id, opts)

      {:error, error} ->
        {:error, error}
    end
  end

  defp locked_renew(installation_id, opts) do
    :global.trans(
      {{__MODULE__, installation_id}, self()},
      fn -> renew(installation_id, opts) end,
      [node()]
    )
  end

  defp renew(installation_id, opts) do
    with {:ok, installation} <- Ash.get(Installation, installation_id, opts) do
      if valid?(installation), do: {:ok, installation.token}, else: mint(installation, opts)
    end
  end

  defp mint(installation, opts) do
    case App.mint(installation.id) do
      {:ok, %{token: token, expires_at: expires_at}} ->
        with {:ok, _stored} <-
               Ash.update(
                 installation,
                 %{token: token, token_expires_at: expires_at},
                 [action: :store_token] ++ opts
               ) do
          {:ok, token}
        end

      {:error, reason} ->
        {:error, RequestFailed.exception(reason: reason)}
    end
  end

  defp valid?(%Installation{token: token, token_expires_at: %DateTime{} = expires_at}) when is_binary(token),
    do: DateTime.diff(expires_at, DateTime.utc_now()) >= @margin_seconds

  defp valid?(_installation), do: false
end
