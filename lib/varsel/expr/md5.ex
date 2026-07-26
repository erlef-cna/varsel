# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Expr.Md5 do
  @moduledoc """
  `md5(value)` — the value's MD5 digest, lowercase hex.

      calculate :avatar_url, :string, expr("https://www.gravatar.com/avatar/" <> md5(email))

  Only for addressing content that is keyed by MD5 elsewhere, such as Gravatar.
  MD5 is not a secure hash and nothing here should treat it as one.
  """
  use Ash.CustomExpression,
    name: :md5,
    arguments: [[:string]]

  @impl Ash.CustomExpression
  def expression(AshPostgres.DataLayer, [value]) do
    {:ok, expr(fragment("md5(?)", ^value))}
  end

  def expression(data_layer, [value]) when data_layer in [Ash.DataLayer.Ets, Ash.DataLayer.Simple] do
    {:ok, expr(fragment(&__MODULE__.hex_digest/1, ^value))}
  end

  def expression(_data_layer, _arguments), do: :unknown

  @doc false
  def hex_digest(nil), do: nil
  def hex_digest(value), do: :md5 |> :crypto.hash(value) |> Base.encode16(case: :lower)
end
