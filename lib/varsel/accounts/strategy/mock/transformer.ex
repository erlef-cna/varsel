# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.Strategy.Mock.Transformer do
  @moduledoc false

  import AshAuthentication.Strategy.Custom.Helpers, only: [register_strategy_actions: 3]

  alias Spark.Dsl.Transformer

  @doc false
  @spec transform(struct, map) :: {:ok, map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    {:ok, resource} = dsl_state |> Transformer.get_persisted(:module) |> then(&{:ok, &1})
    strategy = %{strategy | resource: resource}

    dsl_state =
      dsl_state
      |> Transformer.replace_entity(
        ~w[authentication strategies]a,
        strategy,
        &(&1.name == strategy.name)
      )
      |> then(&register_strategy_actions(strategy.register_action_name, &1, strategy))

    {:ok, dsl_state}
  end
end
