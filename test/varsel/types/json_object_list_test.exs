# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.JsonObjectListTest do
  use ExUnit.Case, async: true

  alias Varsel.Types.JsonObjectList, as: Type

  test "decodes a JSON array of objects" do
    assert {:ok, [%{"a" => 1}, %{"b" => 2}]} =
             Ash.Type.cast_input(Type, ~s([{"a": 1}, {"b": 2}]), [])
  end

  test "an already-decoded list of maps passes through" do
    assert {:ok, [%{"a" => 1}]} = Ash.Type.cast_input(Type, [%{"a" => 1}], [])
  end

  test "nil and blank string cast to nil" do
    assert {:ok, nil} = Ash.Type.cast_input(Type, nil, [])
    assert {:ok, nil} = Ash.Type.cast_input(Type, "", [])
  end

  test "malformed JSON is refused with a message" do
    assert {:error, message: "is not valid JSON"} = Ash.Type.cast_input(Type, "not json", [])
  end

  test "valid JSON that is not an array of objects is refused" do
    assert {:error, message: "must be a JSON array of objects"} =
             Ash.Type.cast_input(Type, ~s({"a": 1}), [])

    assert {:error, message: "must be a JSON array of objects"} =
             Ash.Type.cast_input(Type, ~s([1, 2, 3]), [])
  end

  test "a non-string, non-list value is refused" do
    assert {:error, message: "must be a JSON array of objects"} =
             Ash.Type.cast_input(Type, 123, [])
  end

  test "round-trips through storage" do
    assert {:ok, [%{"a" => 1}]} = Ash.Type.cast_stored(Type, [%{"a" => 1}], [])
    assert {:ok, [%{"a" => 1}]} = Ash.Type.dump_to_native(Type, [%{"a" => 1}], [])
  end
end
