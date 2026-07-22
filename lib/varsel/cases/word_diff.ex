# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.WordDiff do
  @moduledoc """
  Decides whether a suggestion's old/new text values are similar enough to
  render as one merged inline diff (typo/rewording, struck words next to
  their replacement) instead of the stacked old-then-new blocks, and builds
  the segment tree the merged rendering walks.

  Whether to merge is a Dice coefficient over whitespace-tokenized words:
  `2 * eq / (words(old) + words(new)) >= 0.5`, with `eq >= 3` so short
  values (versions, CVSS vectors, one-word titles) can never qualify on a
  coincidental shared word. Both `eq` and the coefficient come from
  `List.myers_difference/2` over the word lists — see `merge?/2`.

  Rendering re-diffs at a finer grain (whitespace runs kept as their own
  tokens, via `Regex.split/3` with `include_captures: true`) so unchanged
  spacing — including paragraph breaks — flows through untouched and only
  a *changed* run gets a visible stand-in (`¶` per newline, `·` per space).
  That second diff also drives paragraph folding: consecutive unchanged
  paragraphs collapse to a fold marker per the rules on `paragraphs/2`.
  """

  @merge_min_eq 3
  @merge_min_similarity 0.5
  @max_combined_tokens 5_000

  @type segment :: {:eq | :del | :ins, String.t()}
  @type paragraph :: {:changed, [segment()]} | {:unchanged, [segment()]}
  @type result :: {:merged, [paragraph()]} | :stacked

  @doc """
  Runs the full decision + segment build for a suggestion's old/new values.

  Returns `:stacked` when either side is blank, the combined token count
  blows the safety valve, or the pair falls below the merge cutoff —
  callers fall back to the existing stacked old/new rows in all those
  cases. Non-binary values never reach this function; callers only diff
  when both sides are plain strings (see `VarselWeb.CaseComponents.suggestion_diff/1`).
  """
  @spec diff(String.t(), String.t()) :: result()
  def diff(old, new) when is_binary(old) and is_binary(new) do
    if merge?(old, new), do: {:merged, paragraphs(old, new)}, else: :stacked
  end

  @doc """
  The merge cutoff: both sides non-empty, at least #{@merge_min_eq} shared
  (whitespace-token) words, and Dice similarity `2*eq/(old+new) >=
  #{@merge_min_similarity}`. Also stacks anything over
  #{@max_combined_tokens} combined tokens rather than diffing pathological
  payloads.
  """
  @spec merge?(String.t(), String.t()) :: boolean()
  def merge?(old, new) when is_binary(old) and is_binary(new) do
    old_words = words(old)
    new_words = words(new)
    total = length(old_words) + length(new_words)

    old != "" and new != "" and total > 0 and total <= @max_combined_tokens and
      merge_by_words?(old_words, new_words, total)
  end

  @doc """
  Emphasis segments for the *stacked* rendering of slash-delimited
  single-token values — CVSS vectors are the driving case: `AV:N` → `AV:L`
  is one changed metric drowned in two near-identical rows, and the word
  cutoff can never merge them (one whitespace-token per side). The rows
  stay stacked; this diffs the two values on `/` boundaries so the rows
  can emphasize just the changed segments.

  Applies only when both sides are non-empty single whitespace-token
  binaries containing `/` and the segment diff shares at least one
  segment; every other pair returns `:plain` (render the rows untouched).
  Old-side segments are `:eq`/`:del`, new-side `:eq`/`:ins`.
  """
  @spec stacked_highlight(String.t() | nil, String.t() | nil) ::
          {:segments, [segment()], [segment()]} | :plain
  def stacked_highlight(old, new) when is_binary(old) and is_binary(new) do
    if slash_value?(old) and slash_value?(new) do
      ops = List.myers_difference(slash_tokens(old), slash_tokens(new))

      if shared_segment?(ops) do
        {:segments, side_segments(ops, :del), side_segments(ops, :ins)}
      else
        :plain
      end
    else
      :plain
    end
  end

  def stacked_highlight(_old, _new), do: :plain

  defp slash_value?(s), do: s != "" and String.contains?(s, "/") and not String.match?(s, ~r/\s/)

  # A shared bare "/" separator alone is not similarity — without a common
  # real segment the emphasis would cover both rows entirely.
  defp shared_segment?(ops) do
    Enum.any?(ops, fn
      {:eq, tokens} -> Enum.any?(tokens, &(&1 != "/"))
      {_kind, _tokens} -> false
    end)
  end

  defp slash_tokens(s), do: Regex.split(~r{/}, s, include_captures: true)

  # One side of the stacked pair: its own changes plus the shared
  # segments, in order — the other side's changes don't exist on this row.
  defp side_segments(ops, kind) do
    ops
    |> Enum.flat_map(fn
      {:eq, tokens} -> [{:eq, IO.iodata_to_binary(tokens)}]
      {^kind, tokens} -> [{kind, IO.iodata_to_binary(tokens)}]
      {_other_side, _tokens} -> []
    end)
    |> coalesce_segments()
  end

  defp merge_by_words?(old_words, new_words, total) do
    eq = old_words |> List.myers_difference(new_words) |> eq_count()
    eq >= @merge_min_eq and 2 * eq / total >= @merge_min_similarity
  end

  defp eq_count(diff_ops) do
    diff_ops
    |> Enum.filter(&match?({:eq, _}, &1))
    |> Enum.map(fn {:eq, tokens} -> length(tokens) end)
    |> Enum.sum()
  end

  defp words(s), do: String.split(s, ~r/\s+/, trim: true)

  @doc """
  Builds the paragraph list for the merged rendering: each paragraph
  (`\\n{2,}`-delimited in the combined token stream) is `:changed` (rendered
  in full — a word diff needs its whole sentence) or `:unchanged` (a
  candidate for folding). Segments inside a paragraph distinguish `:eq` /
  `:del` / `:ins` runs. A whitespace-*only* del/ins op (whitespace itself
  being the change) becomes a tinted `¶`/`·` stand-in segment, trailed for
  `:ins` by a plain `:eq` segment holding the real new whitespace so
  wrapping stays real; a del/ins op mixing words and whitespace (an
  ordinary multi-word run) keeps its interior whitespace literal; unchanged
  whitespace passes through verbatim.

  Folding itself (which `:unchanged` runs actually collapse, vs. the single
  paragraph sandwiched between two edits that stays visible) is decided by
  the caller/component from the returned list — this function only labels
  each paragraph, it does not fold.
  """
  @spec paragraphs(String.t(), String.t()) :: [paragraph()]
  def paragraphs(old, new) do
    old
    |> render_diff(new)
    |> split_paragraph_ops()
    |> Enum.map(&build_paragraph/1)
  end

  defp render_diff(old, new) do
    old
    |> render_tokens()
    |> List.myers_difference(render_tokens(new))
    |> bridge_adjacent_replacements()
  end

  # Myers finds the longest common subsequence, so a phrase-level
  # replacement like "supervision tree" -> "`ThousandIsland.Handler`
  # process" comes back interleaved — del, ins, eq([" "]), del, ins — with
  # the single shared space bridging the two replaced words as real LCS.
  # That's correct as a diff, but renders as four small spans instead of
  # the one del span + one ins span the board shows. Split the ops into
  # maximal islands (a run of del/ins ops, optionally joined by
  # single-token pure-whitespace :eq bridges strictly between two of
  # them) and collapse each island into at most one del segment (all its
  # tokens, in encounter order) followed by one ins segment.
  defp bridge_adjacent_replacements([]), do: []

  defp bridge_adjacent_replacements([op | rest]) do
    if match?({kind, _} when kind in [:del, :ins], op) do
      {island, rest} = take_island(rest, [op])
      collapse_island(island) ++ bridge_adjacent_replacements(rest)
    else
      [op | bridge_adjacent_replacements(rest)]
    end
  end

  # Extends an already-open island (it starts on a :del/:ins) through any
  # further :del/:ins ops and single-token pure-whitespace :eq bridges
  # that sit strictly between two of them; stops at the first op that
  # isn't one of those, or a bridge with nothing replacement-shaped after
  # it (leaving that bridge in `rest`, untouched).
  defp take_island([{kind, _} = op | rest], acc) when kind in [:del, :ins] do
    take_island(rest, [op | acc])
  end

  defp take_island([{:eq, [ws]} = bridge, {kind, _} = op | rest], acc) when kind in [:del, :ins] do
    if whitespace_token?(ws) do
      take_island(rest, [op, bridge | acc])
    else
      {Enum.reverse(acc), [bridge, op | rest]}
    end
  end

  defp take_island(rest, acc), do: {Enum.reverse(acc), rest}

  defp collapse_island(ops) do
    {del_tokens, ins_tokens} =
      Enum.reduce(ops, {[], []}, fn
        {:del, tokens}, {del, ins} -> {del ++ tokens, ins}
        {:ins, tokens}, {del, ins} -> {del, ins ++ tokens}
        {:eq, [ws]}, {del, ins} -> {del ++ [ws], ins ++ [ws]}
      end)

    del = if del_tokens == [], do: [], else: [{:del, del_tokens}]
    ins = if ins_tokens == [], do: [], else: [{:ins, ins_tokens}]
    del ++ ins
  end

  defp render_tokens(s), do: Regex.split(~r/\s+/, s, include_captures: true)

  # Cuts the op list at unchanged whitespace runs containing a paragraph
  # break (>= 2 newlines) — a changed separator (part of a :del/:ins run)
  # stays embedded in whichever paragraph it falls into instead of forcing
  # a split, since there's no single agreed-on boundary to fold around.
  defp split_paragraph_ops(ops) do
    ops
    |> Enum.flat_map(&explode_paragraph_breaks/1)
    |> Enum.chunk_while(
      [],
      fn
        :split, acc -> {:cont, Enum.reverse(acc), []}
        op, acc -> {:cont, [op | acc]}
      end,
      fn acc -> {:cont, Enum.reverse(acc), []} end
    )
    |> Enum.reject(&(&1 == []))
  end

  defp explode_paragraph_breaks({:eq, tokens}) do
    Enum.flat_map(tokens, fn token ->
      if paragraph_break?(token), do: [{:eq, [token]}, :split], else: [{:eq, [token]}]
    end)
  end

  defp explode_paragraph_breaks(op), do: [op]

  defp paragraph_break?(token), do: String.match?(token, ~r/^\s*\n{2,}\s*$/)

  defp build_paragraph(ops) do
    if Enum.any?(ops, &match?({:del, _}, &1)) or Enum.any?(ops, &match?({:ins, _}, &1)) do
      {:changed, build_segments(ops)}
    else
      {:unchanged, build_segments(ops)}
    end
  end

  defp build_segments(ops) do
    ops
    |> Enum.flat_map(&op_segments/1)
    |> coalesce_segments()
  end

  # Word-by-word :eq ops (one per whitespace-preserving token) otherwise
  # produce a long run of single-word segments with identical, plain
  # styling — coalesce adjacent same-kind segments into one for a smaller
  # DOM; harmless for :del/:ins since those already arrive as one run.
  defp coalesce_segments(segments) do
    segments
    |> Enum.reduce([], fn
      {kind, text}, [{kind, acc_text} | rest] -> [{kind, acc_text <> text} | rest]
      segment, acc -> [segment | acc]
    end)
    |> Enum.reverse()
  end

  defp op_segments({:eq, tokens}), do: [{:eq, IO.iodata_to_binary(tokens)}]

  # A whitespace-only del/ins op is whitespace *itself* being the change
  # (e.g. one blank line becoming two) — it renders as a struck/tinted
  # stand-in, with the real new whitespace trailing outside the span so
  # wrapping stays real (an all-del run has no "new" whitespace to trail).
  defp op_segments({kind, tokens}) when kind in [:del, :ins] do
    if Enum.all?(tokens, &whitespace_token?/1) do
      text = IO.iodata_to_binary(tokens)
      stand_in = {kind, whitespace_stand_in(text)}
      if kind == :ins, do: [stand_in, {:eq, text}], else: [stand_in]
    else
      [{kind, IO.iodata_to_binary(tokens)}]
    end
  end

  defp whitespace_token?(""), do: false
  defp whitespace_token?(token), do: String.match?(token, ~r/^\s+$/)

  # One ¶ per newline (paragraph/line breaks), else one · per space/tab
  # run — the caller tints this and, for :ins, trails the real whitespace
  # after it untinted.
  defp whitespace_stand_in(text) do
    newlines = text |> String.graphemes() |> Enum.count(&(&1 == "\n"))
    if newlines > 0, do: String.duplicate("¶", newlines), else: "·"
  end
end
