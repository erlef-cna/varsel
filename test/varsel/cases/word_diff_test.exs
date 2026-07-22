# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.WordDiffTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.WordDiff

  describe "merge?/2" do
    test "a one-word typo fix merges" do
      assert WordDiff.merge?(
               "Bandit HTTP/1 request smugling via bare CR in chunk extensions",
               "Bandit HTTP/1 request smuggling via bare CR in chunk extensions"
             )
    end

    test "a full rewrite that shares too little stays stacked" do
      refute WordDiff.merge?(
               "A denial of service issue exists in the multipart parser.",
               "Plug's multipart parser allocates an unbounded number of temporary files " <>
                 "when parsing deeply nested multipart bodies, allowing a remote attacker " <>
                 "to exhaust disk space and file descriptors on the target host."
             )
    end

    test "an added sentence with substantial shared prefix merges" do
      old = "Upgrade to Bandit 1.5.8 or later."
      new = "Upgrade to Bandit 1.5.8 or later. Also disable chunked transfer at the proxy."

      assert WordDiff.merge?(old, new)
    end

    test "version strings never merge — too few whitespace tokens to reach eq >= 3" do
      refute WordDiff.merge?("1.5.7", "1.5.8")
    end

    test "CVSS vectors never merge — single whitespace-token each side" do
      refute WordDiff.merge?(
               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
               "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H"
             )
    end

    test "one-word titles never merge even when the word is shared" do
      refute WordDiff.merge?("Bandit", "Bandit2")
    end

    test "a whitespace-only change stays merged" do
      assert WordDiff.merge?("line one.\n\nline two.", "line one.\n\n\nline two.")
    end

    test "either side blank stacks (pure addition/removal)" do
      refute WordDiff.merge?("", "Some new sentence with several words in it.")
      refute WordDiff.merge?("Some old sentence with several words in it.", "")
    end

    test "eq boundary: exactly 2 shared words stays stacked, exactly 3 merges" do
      # 3 words each side, 2 shared ("a" and "c"): eq=2, similarity = 4/6 = 0.667 >= 0.5,
      # but eq < 3 so it must stack.
      refute WordDiff.merge?("a b c", "a x c")

      # 4 words each side, 3 shared: eq=3, similarity = 6/8 = 0.75 >= 0.5 -> merges.
      assert WordDiff.merge?("a b c d", "a x c d")
    end

    test "similarity boundary: exactly 0.5 merges, just under stacks" do
      # old has 3 words, new has 5 words, eq=3 shared -> similarity = 6/8 = 0.75.
      # Construct exact boundary cases instead: eq=3, total=12 -> similarity = 0.5.
      old = "a b c d e f"
      new = "a b c x y z"
      # eq = 3 ("a", "b", "c"), total = 12, similarity = 6/12 = 0.5 -> merges.
      assert WordDiff.merge?(old, new)

      # Push total up by one extra unmatched word on each side so eq stays 3
      # but similarity drops under 0.5.
      old2 = "a b c d e f g"
      new2 = "a b c x y z w"
      # eq = 3, total = 14, similarity = 6/14 ~= 0.4286 -> stacks.
      refute WordDiff.merge?(old2, new2)
    end

    test "an oversized combined payload stacks regardless of similarity" do
      old = "word " |> String.duplicate(3000) |> String.trim()
      new = String.trim(String.duplicate("word ", 2999) <> "words")
      refute WordDiff.merge?(old, new)
    end
  end

  describe "stacked_highlight/2" do
    test "a CVSS vector pair highlights just the changed metric on each row" do
      old = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
      new = "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"

      assert {:segments, old_segments, new_segments} = WordDiff.stacked_highlight(old, new)

      assert {:del, "AV:N"} in old_segments
      refute Enum.any?(old_segments, &match?({:ins, _}, &1))
      assert {:ins, "AV:L"} in new_segments
      refute Enum.any?(new_segments, &match?({:del, _}, &1))

      # Each side reassembles to its own full value.
      assert Enum.map_join(old_segments, &elem(&1, 1)) == old
      assert Enum.map_join(new_segments, &elem(&1, 1)) == new
    end

    test "values without a slash stay plain" do
      assert WordDiff.stacked_highlight("1.5.7", "1.5.8") == :plain
    end

    test "prose (anything with whitespace) stays plain" do
      assert WordDiff.stacked_highlight("prose with spaces", "other prose here") == :plain
    end

    test "slash values sharing only the separator stay plain" do
      assert WordDiff.stacked_highlight("a/b", "x/y/z") == :plain
    end

    test "a blank or missing side stays plain" do
      assert WordDiff.stacked_highlight(nil, "CVSS:3.1/AV:N") == :plain
      assert WordDiff.stacked_highlight("", "CVSS:3.1/AV:N") == :plain
    end
  end

  describe "diff/2 segment structure" do
    test "typo fix produces a single changed paragraph with adjacent del/ins segments" do
      old = "Bandit HTTP/1 request smugling via bare CR in chunk extensions"
      new = "Bandit HTTP/1 request smuggling via bare CR in chunk extensions"

      assert {:merged, [{:changed, segments}]} = WordDiff.diff(old, new)
      assert {:del, "smugling"} in segments
      assert {:ins, "smuggling"} in segments

      # Unchanged text appears once, coalesced, not duplicated per word.
      assert Enum.count(segments, &match?({:eq, _}, &1)) == 2
    end

    test "dissimilar values stack instead of returning a paragraph tree" do
      assert WordDiff.diff(
               "A denial of service issue exists in the multipart parser.",
               "Plug's multipart parser allocates an unbounded number of temporary files."
             ) == :stacked
    end

    test "a whitespace-only change renders del/ins stand-ins around the real new whitespace" do
      assert {:merged, [{:changed, segments}]} =
               WordDiff.diff("line one.\n\nline two.", "line one.\n\n\nline two.")

      assert {:del, "¶¶"} in segments
      assert {:ins, "¶¶¶"} in segments
      # The real new whitespace trails the ins stand-in, unstyled.
      assert Enum.any?(segments, fn
               {:eq, text} -> String.contains?(text, "\n\n\n")
               _other -> false
             end)
    end

    test "a single space-only change uses the · stand-in" do
      old = "Upgrade to Bandit 1.5.8 or later now."
      new = "Upgrade to Bandit 1.5.8 or  later now."

      assert {:merged, [{:changed, segments}]} = WordDiff.diff(old, new)
      assert {:del, "·"} in segments
      assert {:ins, "·"} in segments
    end

    test "multi-word del/ins runs render as one span each, not word-by-word" do
      old = "Requests are parsed by the supervision tree before headers are validated."

      new =
        "Requests are parsed by the `ThousandIsland.Handler` process before headers are validated."

      assert {:merged, [{:changed, segments}]} = WordDiff.diff(old, new)
      assert {:del, "supervision tree"} in segments
      assert {:ins, "`ThousandIsland.Handler` process"} in segments
    end

    test "raw markdown syntax prints literally inside changed spans" do
      old = "a single malformed frame crashes the acceptor."
      new = "a **single** malformed frame crashes the acceptor."

      assert {:merged, [{:changed, segments}]} = WordDiff.diff(old, new)
      assert {:ins, "**single**"} in segments
    end
  end

  describe "paragraph fold rules" do
    defp fixture_paragraphs do
      old = """
      First paragraph has a typo in it.

      Middle paragraph is identical in both versions, sandwiched.

      Last paragraph also has a typo here.
      """

      new = """
      First paragraph has a typoo in it.

      Middle paragraph is identical in both versions, sandwiched.

      Last paragraph also has a typoo here.
      """

      {old, new}
    end

    test "a run of >= 2 unchanged paragraphs is a fold candidate (labeled :unchanged)" do
      old = """
      Paragraph with a typo goes here.

      Second untouched paragraph.

      Third untouched paragraph.

      Last paragraph also has a typo appended here now.
      """

      new = """
      Paragraph with a typoo goes here.

      Second untouched paragraph.

      Third untouched paragraph.

      Last paragraph also has a typoo appended here now.
      """

      assert {:merged, paragraphs} = WordDiff.diff(old, new)
      assert Enum.map(paragraphs, &elem(&1, 0)) == [:changed, :unchanged, :unchanged, :changed]
    end

    test "a single unchanged paragraph strictly between two changes is still labeled :unchanged" do
      {old, new} = fixture_paragraphs()

      assert {:merged, paragraphs} = WordDiff.diff(old, new)
      assert Enum.map(paragraphs, &elem(&1, 0)) == [:changed, :unchanged, :changed]
    end

    test "a leading unchanged paragraph is labeled :unchanged (edge, folds even alone)" do
      old = """
      Untouched leading paragraph stays the same in both.

      Second paragraph has a typo in it.
      """

      new = """
      Untouched leading paragraph stays the same in both.

      Second paragraph has a typoo in it.
      """

      assert {:merged, paragraphs} = WordDiff.diff(old, new)
      assert Enum.map(paragraphs, &elem(&1, 0)) == [:unchanged, :changed]
    end

    test "a trailing unchanged paragraph is labeled :unchanged (edge, folds even alone)" do
      old = """
      First paragraph has a typo in it.

      Untouched trailing paragraph stays the same in both.
      """

      new = """
      First paragraph has a typoo in it.

      Untouched trailing paragraph stays the same in both.
      """

      assert {:merged, paragraphs} = WordDiff.diff(old, new)
      assert Enum.map(paragraphs, &elem(&1, 0)) == [:changed, :unchanged]
    end
  end
end
