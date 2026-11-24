# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.Sections do
  @moduledoc """
  Reads a GitHub advisory description as the sections of
  `Varsel.CVE.Advisory`, and writes one section back into it.

  A section starts at a level-3 heading with the section's name and runs to
  the next heading of level 3 or above. Names match case-insensitively.
  GitHub's template spells the proof of concept `PoC`. All other content is
  unmapped: text before the first heading, a heading with another name or
  level, and a section named a second time. A description with no section
  heading is all summary.

  Each section is a diff field. The summary is the `description` field. Six
  sections map to a markdown attribute of the case. Impact and References
  map to rows of the case, which their prose cannot rebuild, so they have no
  attribute.
  """

  alias Varsel.CVE.Advisory

  @fields [
    description: {:summary, :description_md},
    details: {:details, :technical_analysis_md},
    proof_of_concept: {:proof_of_concept, :proof_of_concept_md},
    impact: {:impact, nil},
    workarounds: {:workarounds, :workarounds_md},
    configurations: {:configurations, :configurations_md},
    solutions: {:solutions, :solutions_md},
    references: {:references, nil}
  ]

  @aliases %{"poc" => :proof_of_concept}

  @names Map.merge(
           Map.new(Advisory.sections(), fn {section, heading} ->
             {String.downcase(heading), section}
           end),
           @aliases
         )

  @order Advisory.keys()

  @type field ::
          :description
          | :details
          | :proof_of_concept
          | :impact
          | :workarounds
          | :configurations
          | :solutions
          | :references

  @typedoc """
  A parsed description: the body of each section found, and every piece of
  unmapped content with the heading line it stands under (nil before the
  first heading).
  """
  @type t :: %{
          sections: %{Advisory.section() => String.t()},
          unmapped: [%{heading: String.t() | nil, body: String.t()}]
        }

  @doc "Every section field, in render order."
  @spec fields() :: [field()]
  def fields, do: Keyword.keys(@fields)

  @doc "The section fields a pull can write to the case."
  @spec pullable_fields() :: [field()]
  def pullable_fields, do: for({field, {_section, attribute}} <- @fields, attribute, do: field)

  @doc "The `Varsel.CVE.Advisory` section of a field."
  @spec section(field()) :: Advisory.section()
  def section(field), do: @fields |> Keyword.fetch!(field) |> elem(0)

  @doc "The case attribute a field pulls into, or nil."
  @spec attribute(field()) :: atom() | nil
  def attribute(field), do: @fields |> Keyword.fetch!(field) |> elem(1)

  @doc "The section bodies and the unmapped content of `text`."
  @spec parse(String.t() | nil) :: t()
  def parse(text) do
    text
    |> blocks()
    |> Enum.reduce(%{sections: %{}, unmapped: []}, fn
      %{section: nil, heading: heading, body: body}, acc ->
        if body == "" and is_nil(heading),
          do: acc,
          else: %{acc | unmapped: acc.unmapped ++ [%{heading: heading, body: body}]}

      %{section: section, body: body}, acc ->
        if body == "", do: acc, else: put_in(acc, [:sections, section], body)
    end)
  end

  @doc """
  `text` with the body of `section` replaced by `body`. A section `text` does
  not have goes in before the first section that follows it in render order,
  or at the end. All other content stays.
  """
  @spec splice(String.t() | nil, Advisory.section(), String.t()) :: String.t()
  def splice(text, section, body) do
    blocks = blocks(text)

    blocks =
      if Enum.any?(blocks, &(&1.section == section)),
        do: Enum.map(blocks, &if(&1.section == section, do: %{&1 | body: body}, else: &1)),
        else: insert(blocks, %{section: section, heading: nil, body: body})

    blocks
    |> Enum.reject(&(&1 == %{section: nil, heading: nil, body: ""}))
    |> Enum.map_join("\n\n", &render_block/1)
  end

  defp insert(blocks, block) do
    position = rank(block.section)

    index =
      Enum.find_index(blocks, &(&1.section && rank(&1.section) > position)) || length(blocks)

    List.insert_at(blocks, index, block)
  end

  defp rank(section), do: Enum.find_index(@order, &(&1 == section))

  defp render_block(%{section: section, heading: nil, body: body}) when not is_nil(section),
    do: join_heading("### #{Keyword.fetch!(Advisory.sections(), section)}", body)

  defp render_block(%{heading: nil, body: body}), do: body
  defp render_block(%{heading: heading, body: body}), do: join_heading(heading, body)

  defp join_heading(heading, ""), do: heading
  defp join_heading(heading, body), do: heading <> "\n\n" <> body

  # Each block is a heading line (nil for the text before the first heading)
  # with its trimmed body and the section it opens. A section block from a
  # description with no section heading carries no heading line.
  defp blocks(nil), do: []

  defp blocks(text) do
    text = String.replace(text, "\r\n", "\n")
    lines = String.split(text, "\n")
    {:ok, document} = MDEx.parse_document(text)

    headings =
      for %MDEx.Heading{level: level, sourcepos: %{start: {first, _}, end: {last, _}}} <-
            document.nodes,
          level <= 3,
          do: {first, last, level}

    blocks = split(lines, headings)

    if Enum.any?(blocks, & &1.section),
      do: blocks,
      else: summary_only(text)
  end

  defp summary_only(text) do
    case String.trim(text) do
      "" -> []
      body -> [%{section: :summary, heading: nil, body: body}]
    end
  end

  defp split(lines, headings) do
    starts = Enum.map(headings, fn {first, _last, _level} -> first end)
    preamble = body(lines, 1, List.first(starts, length(lines) + 1) - 1)
    ends = Enum.map(Enum.drop(starts, 1), &(&1 - 1)) ++ [length(lines)]

    {blocks, _seen} =
      headings
      |> Enum.zip(ends)
      |> Enum.map_reduce(MapSet.new(), fn {{first, last, level}, stop}, seen ->
        heading =
          lines |> Enum.slice((first - 1)..(last - 1)//1) |> Enum.join(" ") |> String.trim()

        section = section_of(heading, level, seen)
        block = %{section: section, heading: heading, body: body(lines, last + 1, stop)}
        {block, if(section, do: MapSet.put(seen, section), else: seen)}
      end)

    [%{section: nil, heading: nil, body: preamble} | blocks]
  end

  defp body(_lines, first, last) when first > last, do: ""

  defp body(lines, first, last), do: lines |> Enum.slice((first - 1)..(last - 1)//1) |> Enum.join("\n") |> String.trim()

  defp section_of(heading, 3, seen) do
    name =
      heading
      |> String.replace(~r/^#+\s*/, "")
      |> String.replace(~r/\s+#+\s*$/, "")
      |> String.trim()
      |> String.downcase()

    case Map.fetch(@names, name) do
      {:ok, section} -> if MapSet.member?(seen, section), do: nil, else: section
      :error -> nil
    end
  end

  defp section_of(_heading, _level, _seen), do: nil
end
