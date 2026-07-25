# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Expr.Coalesce do
  @moduledoc """
  `coalesce([a, b, c])` — the first element that is not `nil`.

      calculate :display_name, :string, expr(coalesce([name, github_handle, email, "user"]))
  """
  use Ash.CustomExpression,
    name: :coalesce,
    arguments: [
      [{:array, :string}],
      [{:array, :integer}],
      [{:array, :uuid}]
    ]

  @impl Ash.CustomExpression
  def expression(AshPostgres.DataLayer, [values]) do
    {:ok,
     expr(
       fragment(
         "(SELECT coalesced FROM unnest(?) AS coalesced WHERE coalesced IS NOT NULL LIMIT 1)",
         ^values
       )
     )}
  end

  def expression(data_layer, [values]) when data_layer in [Ash.DataLayer.Ets, Ash.DataLayer.Simple] do
    {:ok, expr(fragment(&__MODULE__.first_present/1, ^values))}
  end

  def expression(_data_layer, _arguments), do: :unknown

  @doc false
  def first_present(values), do: Enum.find(values, &(not is_nil(&1)))
end
