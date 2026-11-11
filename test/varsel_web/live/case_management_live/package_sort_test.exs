# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive.PackageSortTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CaseManagementLive.PackageSort

  defp row(label, opts \\ []) do
    now = ~U[2026-11-11 12:00:00.000000Z]

    %{
      label: label,
      total: Keyword.get(opts, :total, 1),
      opened_at: DateTime.shift(now, day: -Keyword.get(opts, :opened_days_ago, 1)),
      max_score: Keyword.get(opts, :max_score),
      updated_at: DateTime.shift(now, hour: -Keyword.get(opts, :updated_hours_ago, 1))
    }
  end

  defp labels(rows, order), do: rows |> PackageSort.sort(order) |> Enum.map(& &1.label)

  describe "parse/1 and param/1" do
    test "every option round-trips, with the default left out of the URL" do
      for {value, _label} <- PackageSort.options() do
        assert PackageSort.parse(Atom.to_string(value)) == value
      end

      assert PackageSort.param(PackageSort.default()) == nil

      for {value, _label} <- PackageSort.options(), value != PackageSort.default() do
        assert value |> PackageSort.param() |> PackageSort.parse() == value
      end
    end

    test "an unknown or missing value takes the default" do
      assert PackageSort.parse("sideways") == PackageSort.default()
      assert PackageSort.parse(nil) == PackageSort.default()
    end
  end

  describe "sort/2" do
    test "most cases first, ties by name" do
      rows = [row("cowboy"), row("plug", total: 3), row("bandit")]

      assert labels(rows, :cases) == ["plug", "bandit", "cowboy"]
    end

    test "name ignores case" do
      assert labels([row("plug"), row("Ash"), row("cowboy")], :name) == ["Ash", "cowboy", "plug"]
    end

    test "oldest case puts the row whose case was opened first on top" do
      rows = [
        row("fresh", opened_days_ago: 1),
        row("ancient", opened_days_ago: 80),
        row("middle", opened_days_ago: 30)
      ]

      assert labels(rows, :oldest) == ["ancient", "middle", "fresh"]
    end

    test "highest severity puts unscored rows last" do
      rows = [row("unscored"), row("high", max_score: 8.2), row("critical", max_score: 9.4)]

      assert labels(rows, :severity) == ["critical", "high", "unscored"]
    end

    test "latest update, the default, puts the row with the most recently updated case on top" do
      rows = [row("quiet", updated_hours_ago: 50), row("busy", updated_hours_ago: 1)]

      assert PackageSort.default() == :recent
      assert labels(rows, :recent) == ["busy", "quiet"]
    end
  end
end
