# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.MergePatchTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Render.MergePatch

  test "nil patch is a no-op" do
    assert MergePatch.apply(%{"a" => 1}, nil) == %{"a" => 1}
  end

  test "objects merge recursively" do
    target = %{"a" => %{"b" => 1, "c" => 2}, "d" => 3}
    patch = %{"a" => %{"b" => 9}}

    assert MergePatch.apply(target, patch) == %{"a" => %{"b" => 9, "c" => 2}, "d" => 3}
  end

  test "nil values delete keys" do
    assert MergePatch.apply(%{"a" => 1, "b" => 2}, %{"a" => nil}) == %{"b" => 2}
  end

  test "arrays and scalars replace wholesale" do
    assert MergePatch.apply(%{"a" => [1, 2]}, %{"a" => [3]}) == %{"a" => [3]}
    assert MergePatch.apply(%{"a" => %{"deep" => true}}, %{"a" => "flat"}) == %{"a" => "flat"}
  end

  test "patching a non-object target with an object builds it up" do
    assert MergePatch.apply("scalar", %{"a" => 1}) == %{"a" => 1}
  end
end
