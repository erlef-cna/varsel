# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.DisplayTest do
  @moduledoc """
  The workspace timeline: which spans of a channel's versions are drawn as
  vulnerable, and where their boundary nodes land.
  """
  use ExUnit.Case, async: true

  alias Varsel.Cases.Derivation.Display
  alias Varsel.Cases.PackageChannel

  defp package(versions, default_status, opts \\ []) do
    %{
      derivation_cache: %{
        "channels" => %{
          "c1" => %{
            "versions" => versions,
            "default_status" => default_status,
            "pending" => Keyword.get(opts, :pending, [])
          }
        }
      },
      channels: [
        %PackageChannel{id: "c1", kind: :package, purl_type: "hex", name: "acme", position: 0}
      ]
    }
  end

  defp affected(version, less_than) do
    %{
      "version" => version,
      "lessThan" => less_than,
      "status" => "affected",
      "versionType" => "semver"
    }
  end

  defp unaffected(version, less_than) do
    %{
      "version" => version,
      "lessThan" => less_than,
      "status" => "unaffected",
      "versionType" => "semver"
    }
  end

  defp kinds(row), do: Enum.map(row.nodes, &{&1.kind, &1.tag})

  describe "an unaffected default" do
    test "one affected range becomes one span between two nodes" do
      assert [row] = Display.timeline_rows(package([affected("1.0.0", "1.5.3")], "unaffected"))

      assert kinds(row) == [{:intro, "1.0.0"}, {:fix, "1.5.3"}]
      assert [%{start: start, stop: stop}] = row.spans
      assert start > 0 and stop < 100
    end

    test "an open range runs off the right edge" do
      assert [row] = Display.timeline_rows(package([affected("1.0.0", "*")], "unaffected"))

      assert kinds(row) == [{:intro, "1.0.0"}]
      assert [%{stop: 100}] = row.spans
    end

    test "the zero bound runs off the left edge" do
      assert [row] = Display.timeline_rows(package([affected("0", "1.5.3")], "unaffected"))

      assert kinds(row) == [{:fix, "1.5.3"}]
      assert [%{start: 0}] = row.spans
    end

    test "explicit unaffected rows are the gaps, not spans" do
      versions = [affected("1.0.0", "1.5.3"), unaffected("1.5.3", "*")]

      assert [row] = Display.timeline_rows(package(versions, "unknown"))

      assert kinds(row) == [{:intro, "1.0.0"}, {:fix, "1.5.3"}]
    end
  end

  describe "an affected default" do
    # The record lists what is safe, so the vulnerable spans are the gaps
    # between those rows.
    test "the span below the only fix runs off the left edge" do
      assert [row] = Display.timeline_rows(package([unaffected("1.5.3", "*")], "affected"))

      assert kinds(row) == [{:fix, "1.5.3"}]
      assert [%{start: 0}] = row.spans
    end

    test "a gap between two safe spans is drawn" do
      versions = [unaffected("1.2.0", "2.0.0"), unaffected("3.0.0", "*")]

      assert [row] = Display.timeline_rows(package(versions, "affected"))

      assert kinds(row) == [{:fix, "1.2.0"}, {:intro, "2.0.0"}, {:fix, "3.0.0"}]

      # Below the first fix, then between the two safe spans.
      assert [%{start: 0, stop: first_fix}, %{start: gap_start, stop: gap_stop}] = row.spans
      assert first_fix < gap_start and gap_start < gap_stop
    end

    # `"0"` opens the track, so a safe span starting there leaves no gap below
    # it to draw.
    test "a safe span from the start of history opens no span below it" do
      versions = [unaffected("0", "2.0.0"), unaffected("3.0.0", "*")]

      assert [row] = Display.timeline_rows(package(versions, "affected"))

      assert kinds(row) == [{:intro, "2.0.0"}, {:fix, "3.0.0"}]
      assert [%{start: start}] = row.spans
      assert start > 0
    end

    test "everything safe draws no row" do
      assert Display.timeline_rows(package([unaffected("0", "*")], "affected")) == []
    end

    # Only a hand-written versions_override produces one, and it says outright
    # which versions are vulnerable.
    test "an explicit affected row is drawn as itself" do
      versions = [affected("1.0.0", "1.5.3"), unaffected("2.0.0", "*")]

      assert [row] = Display.timeline_rows(package(versions, "affected"))

      assert kinds(row) == [{:intro, "1.0.0"}, {:fix, "1.5.3"}]
    end

    # Nothing is listed as safe, so the whole track is vulnerable.
    test "no rows at all still draws a row" do
      assert [row] = Display.timeline_rows(package([], "affected"))

      assert row.nodes == []
      assert [%{start: 0, stop: 100}] = row.spans
    end
  end

  describe "channel_derivations/1" do
    test "surfaces the default status the record publishes" do
      pkg = package([affected("1.0.0", "1.5.3")], "unknown")

      assert [{_channel, derived}] = Display.channel_derivations(pkg)
      assert derived.default_status == "unknown"
    end

    test "a channel with no cached derivation has no default status to state" do
      pkg = %{derivation_cache: nil, channels: [%PackageChannel{id: "c1", position: 0}]}

      assert [{_channel, derived}] = Display.channel_derivations(pkg)
      assert derived.default_status == nil
      assert derived.versions == []
    end
  end

  describe "rows with nothing to draw" do
    test "a git-sha channel produces no row" do
      versions = [
        %{
          "version" => "abc",
          "lessThan" => "def",
          "status" => "affected",
          "versionType" => "git"
        }
      ]

      assert Display.timeline_rows(package(versions, "unaffected")) == []
    end

    test "an uncached package produces no rows" do
      assert Display.timeline_rows(%{derivation_cache: nil}) == []
    end

    test "a pending fix draws a row of its own" do
      assert [row] = Display.timeline_rows(package([], "unaffected", pending: ["abc"]))

      assert kinds(row) == [{:pending, "fix unreleased"}]
    end
  end
end
