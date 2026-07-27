# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Mock.Actions do
  @moduledoc false

  alias Ash.Changeset
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info

  @doc false
  @spec register(struct, map, keyword) :: {:ok, Ash.Resource.Record.t()} | {:error, any}
  def register(strategy, params, options) do
    options = Keyword.put_new_lazy(options, :domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_create(
      strategy.register_action_name,
      params,
      Keyword.put(options, :upsert?, true)
    )
    |> Ash.create()
    |> case do
      {:ok, user} ->
        {:ok, user}

      {:error, error} ->
        {:error, AuthenticationFailed.exception(strategy: strategy, caused_by: error)}
    end
  end
end
