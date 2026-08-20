# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.JsonObjectList do
  @moduledoc """
  Custom Ash type for a list of JSON objects, stored as `{:array, :map}`.

  `Ash.Type.cast_input({:array, _type}, term, _)` rejects a bare string before
  the inner type ever runs, so an `{:array, :map}` attribute cannot accept
  JSON text the way a plain `:map` attribute can (`Ash.Type.Map.cast_input/2`
  decodes a string itself). This type decodes a JSON string into a list of
  maps as one non-array scalar, so form and API callers can submit raw JSON
  text for a field whose stored shape is an array of objects.
  """

  @behaviour AshGraphql.Type

  use Ash.Type

  @impl AshGraphql.Type
  def graphql_type(_constraints), do: :json

  @impl AshGraphql.Type
  def graphql_input_type(_constraints), do: :json

  @impl Ash.Type
  def storage_type(_constraints), do: {:array, :map}

  @impl Ash.Type
  def cast_input(nil, _constraints), do: {:ok, nil}
  def cast_input("", _constraints), do: {:ok, nil}
  def cast_input(value, _constraints) when is_list(value), do: cast_list(value)

  def cast_input(value, constraints) when is_binary(value) do
    case JSON.decode(value) do
      {:ok, decoded} -> cast_input(decoded, constraints)
      {:error, _reason} -> {:error, message: "is not valid JSON"}
    end
  end

  def cast_input(_value, _constraints), do: {:error, message: "must be a JSON array of objects"}

  defp cast_list(list) do
    if Enum.all?(list, &is_map/1) do
      {:ok, list}
    else
      {:error, message: "must be a JSON array of objects"}
    end
  end

  @impl Ash.Type
  def cast_stored(nil, _constraints), do: {:ok, nil}
  def cast_stored(value, _constraints) when is_list(value), do: {:ok, value}
  def cast_stored(_value, _constraints), do: :error

  @impl Ash.Type
  def dump_to_native(nil, _constraints), do: {:ok, nil}
  def dump_to_native(value, _constraints) when is_list(value), do: {:ok, value}
  def dump_to_native(_value, _constraints), do: :error
end
