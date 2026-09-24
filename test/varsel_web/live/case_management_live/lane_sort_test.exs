# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive.LaneSortTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CaseManagementLive.LaneSort

  defp card(name, opts) do
    %{
      name: name,
      title: Keyword.get(opts, :title),
      cvss_score: Keyword.get(opts, :cvss_score),
      updated_at: DateTime.shift(~U[2026-01-01 00:00:00Z], day: Keyword.get(opts, :age, 0))
    }
  end

  defp names(cards, order), do: cards |> LaneSort.sort(order) |> Enum.map(& &1.name)

  describe "parse/1" do
    test "reads every known order" do
      for {value, _label} <- LaneSort.options() do
        assert LaneSort.parse(Atom.to_string(value)) == value
      end
    end

    test "an unknown or absent value takes the default" do
      assert LaneSort.parse("sideways") == LaneSort.default()
      assert LaneSort.parse(nil) == LaneSort.default()
      assert LaneSort.parse("") == LaneSort.default()
    end
  end

  describe "param/1" do
    test "the default is left out of the URL" do
      assert LaneSort.param(LaneSort.default()) == nil
    end

    test "every other order round-trips" do
      for {value, _label} <- LaneSort.options(), value != LaneSort.default() do
        assert value |> LaneSort.param() |> LaneSort.parse() == value
      end
    end
  end

  describe "sort/2" do
    setup do
      %{
        cards: [
          card("old", age: 0),
          card("new", age: 10),
          card("middle", age: 5)
        ]
      }
    end

    test "newest first is the default order", %{cards: cards} do
      assert names(cards, :newest) == ["new", "middle", "old"]
      assert LaneSort.default() == :newest
    end

    test "oldest first reverses it", %{cards: cards} do
      assert names(cards, :oldest) == ["old", "middle", "new"]
    end

    test "severity ranks high scores first" do
      cards = [
        card("low", cvss_score: 2.1),
        card("critical", cvss_score: 9.8),
        card("medium", cvss_score: 5.5)
      ]

      assert names(cards, :severity) == ["critical", "medium", "low"]
    end

    test "title sorts alphabetically, ignoring case" do
      cards = [card("b", title: "beam"), card("a", title: "Ash"), card("c", title: "cowboy")]

      assert names(cards, :title) == ["a", "b", "c"]
    end
  end

  describe "sort/2 — rows the column cannot rank" do
    test "unscored cases sort last, then newest first" do
      cards = [
        card("unscored_old", age: 0),
        card("scored", cvss_score: 4.0, age: 1),
        card("unscored_new", age: 9)
      ]

      assert names(cards, :severity) == ["scored", "unscored_new", "unscored_old"]
    end

    test "untitled cases sort last under title" do
      cards = [card("untitled", age: 0), card("titled", title: "zzz", age: 1)]

      assert names(cards, :title) == ["titled", "untitled"]
    end

    test "equal values break the tie on newest first" do
      cards = [
        card("same_old", cvss_score: 7.0, age: 0),
        card("same_new", cvss_score: 7.0, age: 4),
        card("same_mid", cvss_score: 7.0, age: 2)
      ]

      assert names(cards, :severity) == ["same_new", "same_mid", "same_old"]
    end

    test "every order is total: no card is dropped or duplicated" do
      cards =
        for index <- 1..12 do
          card("c#{index}",
            age: rem(index * 5, 7),
            cvss_score: if(rem(index, 3) == 0, do: nil, else: rem(index * 7, 10) / 1),
            title: if(rem(index, 4) == 0, do: nil, else: "t#{rem(index * 3, 5)}")
          )
        end

      for {order, _label} <- LaneSort.options() do
        sorted = LaneSort.sort(cards, order)

        assert length(sorted) == length(cards)
        assert MapSet.new(sorted, & &1.name) == MapSet.new(cards, & &1.name)
      end
    end
  end
end
