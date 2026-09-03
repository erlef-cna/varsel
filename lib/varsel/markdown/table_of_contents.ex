# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Markdown.TableOfContents do
  @moduledoc """
  The table of contents a rendered document's sidebar lists, taken from its
  headings.
  """

  @type entry :: %{level: pos_integer(), id: String.t(), text: String.t()}

  # The levels a docs sidebar renders.
  @levels [2, 3]

  @doc """
  The `##`/`###` headings of `document`, in the order they appear.

  Each entry's `id` is the fragment Comrak gives the heading under
  `header_id_prefix`, so it addresses that heading's own anchor.
  """
  @spec build(MDEx.Document.t()) :: [entry()]
  def build(document) do
    {_document, entries} =
      MDEx.traverse_and_update(document, [], fn
        %MDEx.Heading{level: level, nodes: nodes} = heading, acc when level in @levels ->
          text = text(nodes)
          {heading, [%{level: level, id: slug(text), text: text} | acc]}

        node, acc ->
          {node, acc}
      end)

    Enum.reverse(entries)
  end

  # Comrak drops everything but alphanumerics, spaces and hyphens, so
  # "Process & Tooling" becomes "process--tooling". These are the fragments the
  # document's own anchors link to, so they are matched rather than tidied.
  defp slug(text) do
    text
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9 \-]/u, "")
    |> String.replace(" ", "-")
  end

  defp text(nodes) do
    nodes
    |> Enum.map_join(&node_text/1)
    |> String.trim()
  end

  defp node_text(%MDEx.Text{literal: literal}), do: literal
  defp node_text(%MDEx.Code{literal: literal}), do: literal
  defp node_text(%{nodes: nodes}), do: Enum.map_join(nodes, &node_text/1)
  defp node_text(_node), do: ""
end
