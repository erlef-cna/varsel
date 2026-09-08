# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.Advisory do
  @moduledoc """
  Renders a CNA container as one markdown advisory: a heading per prose
  section, in a fixed order, from whichever sections the caller includes.

  Each section takes its text from the record's English entry, markdown
  source first (`supportingMedia` text/markdown) and the plain `value` with
  its markdown punctuation escaped otherwise. References list as one bullet
  per URL, prefixed by the reference's name when it has one. A section the
  record does not carry renders nothing, so the caller's selection only ever
  narrows.
  """

  @sections [
    summary: "Summary",
    details: "Details",
    proof_of_concept: "Proof of concept",
    impact: "Impact",
    workarounds: "Workarounds",
    configurations: "Configurations",
    solutions: "Solutions",
    references: "References"
  ]

  @keys Keyword.keys(@sections)

  @type section ::
          :summary
          | :details
          | :proof_of_concept
          | :impact
          | :workarounds
          | :configurations
          | :solutions
          | :references

  @doc "Every section the advisory can carry, `{key, heading}` in render order."
  @spec sections() :: [{section(), String.t()}]
  def sections, do: @sections

  @doc "The section keys, in render order."
  @spec keys() :: [section()]
  def keys, do: @keys

  @doc """
  The advisory markdown for the given sections of a CNA container. Sections
  render in the order of `sections/0` whatever order they are given in.
  `heading_level:` is the heading rank of a section, 2 unless given.
  """
  @spec render(map(), [section()], heading_level: 1..6) :: String.t()
  def render(cna, included, opts \\ []) when is_map(cna) and is_list(included) do
    marks = String.duplicate("#", Keyword.get(opts, :heading_level, 2))

    for_result =
      for {key, heading} <- @sections, key in included, text = text(cna, key), text != "" do
        "#{marks} #{heading}\n\n#{text}"
      end

    Enum.join(for_result, "\n\n")
  end

  defp text(cna, :summary), do: cna["descriptions"] |> english_entry() |> markdown()
  defp text(cna, :details), do: cna["x_technicalAnalysis"] |> english_entry() |> markdown()
  defp text(cna, :proof_of_concept), do: cna["x_proofOfConcept"] |> english_entry() |> markdown()
  defp text(cna, :workarounds), do: cna["workarounds"] |> english_entry() |> markdown()
  defp text(cna, :configurations), do: cna["configurations"] |> english_entry() |> markdown()
  defp text(cna, :solutions), do: cna["solutions"] |> english_entry() |> markdown()

  # One paragraph per impact entry that carries authored prose. A description
  # that only restates the entry's CAPEC id is the label the render emits for
  # an entry without any (see `Varsel.Cases.Case.Calculations.Preview`).
  defp text(cna, :impact) do
    for_result =
      for impact <- List.wrap(cna["impacts"]),
          entry = english_entry(impact["descriptions"]),
          not capec_label?(entry, impact["capecId"]),
          text = markdown(entry),
          text != "" do
        text
      end

    Enum.join(for_result, "\n\n")
  end

  defp text(cna, :references) do
    for_result =
      for reference <- List.wrap(cna["references"]), url = reference["url"], is_binary(url) do
        case reference["name"] do
          name when is_binary(name) and name != "" -> "* #{name}: #{url}"
          _none -> "* #{url}"
        end
      end

    Enum.join(for_result, "\n")
  end

  defp english_entry(entries) do
    entries |> List.wrap() |> Enum.find(&(is_map(&1) and &1["lang"] == "en"))
  end

  defp capec_label?(nil, _capec_id), do: false

  defp capec_label?(entry, capec_id) when is_binary(capec_id) do
    String.starts_with?(entry["value"] || "", capec_id)
  end

  defp capec_label?(_entry, _capec_id), do: false

  defp markdown(nil), do: ""

  defp markdown(entry) do
    source =
      entry["supportingMedia"]
      |> List.wrap()
      |> Enum.find_value(fn media ->
        if media["type"] == "text/markdown" and media["base64"] != true, do: media["value"]
      end)

    case_result =
      case source do
        nil -> entry["value"] |> Kernel.||("") |> escape()
        markdown -> markdown
      end

    String.trim(case_result)
  end

  defp escape(text), do: String.replace(text, ~r/([_*\[\]`\\])/, "\\\\\\1")
end
