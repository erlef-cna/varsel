# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.RangesTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.GitHubAdvisory.Ranges

  describe "format/2" do
    test "writes a span the way GitHub does" do
      assert Ranges.format("1.0.0", "1.2.3") == ">= 1.0.0, < 1.2.3"
      assert Ranges.format("2.0.0", nil) == ">= 2.0.0"
      assert Ranges.format(nil, "0.9.1") == "< 0.9.1"
      assert Ranges.format(nil, nil) == ">= 0"
    end

    test "the zero bound opens the span below" do
      assert Ranges.format("0", "1.2.3") == "< 1.2.3"
      assert Ranges.format("0", nil) == ">= 0"
    end
  end

  describe "normalize/1" do
    test "gives one range GitHub's spacing" do
      assert Ranges.normalize(">=1.0.0,<1.2.3") == ">= 1.0.0, < 1.2.3"
      assert Ranges.normalize(" <  2.0 ") == "< 2.0"
      assert Ranges.normalize("1.0.0") == "= 1.0.0"
      assert Ranges.normalize(">= 17.0") == ">= 17.0"
    end

    test "blank is nil" do
      assert Ranges.normalize(nil) == nil
      assert Ranges.normalize("  ") == nil
    end
  end

  test "split_versions/1 reads a patched_versions list" do
    assert Ranges.split_versions("29.0.6, 28.5.0.6,27.3.4.17") == [
             "29.0.6",
             "28.5.0.6",
             "27.3.4.17"
           ]

    assert Ranges.split_versions(nil) == []
    assert Ranges.split_versions("") == []
  end
end
