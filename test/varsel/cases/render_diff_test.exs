# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Render.DiffTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Render.Diff

  test "identical containers diff to unchanged lines only" do
    cna = %{"title" => "Same", "source" => %{"discovery" => "EXTERNAL"}}

    lines = Diff.lines(cna, cna)

    refute Diff.changed?(lines)
    refute Enum.any?(lines, &match?({:del, _}, &1))
    refute Enum.any?(lines, &match?({:ins, _}, &1))
  end

  test "key order does not produce phantom changes" do
    # Maps with > 32 keys get arbitrary iteration order; the stable
    # serialization must sort them.
    old = Map.new(1..40, fn i -> {"key_#{i}", i} end)
    new = old |> Enum.shuffle() |> Map.new()

    refute Diff.changed?(Diff.lines(old, new))
  end

  test "changed values show as del/ins pairs" do
    old = %{"title" => "Old title", "keep" => true}
    new = %{"title" => "New title", "keep" => true}

    lines = Diff.lines(old, new)

    assert Diff.changed?(lines)
    assert Enum.any?(lines, &match?({:del, ~s(  "title": "Old title") <> _}, &1))
    assert Enum.any?(lines, &match?({:ins, ~s(  "title": "New title") <> _}, &1))
  end

  test "long unchanged runs collapse to their edges" do
    old = Map.new(1..30, fn i -> {"key_#{String.pad_leading(to_string(i), 2, "0")}", i} end)
    new = Map.put(old, "key_30", "changed")

    lines = Diff.lines(old, new)

    assert Enum.any?(lines, &match?({:skip, count} when count > 0, &1))
    assert Enum.count(lines, &match?({:eq, _}, &1)) < 30
  end
end
