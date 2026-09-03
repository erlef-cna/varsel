# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Markdown.Plaintext do
  @moduledoc """
  Renders a markdown document as plain text, for the places that carry prose
  without markup.
  """

  @doc """
  The text of `document`: one paragraph per block, list items bulleted, and
  links keeping both their text and their target.
  """
  @spec render(MDEx.Document.t()) :: String.t()
  def render(%MDEx.Document{nodes: nodes}) do
    nodes
    |> Enum.map(&block_text/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n\n")
    |> String.trim()
  end

  defp block_text(%MDEx.List{nodes: items}) do
    Enum.map_join(items, "\n", fn item -> "* " <> block_text(item) end)
  end

  defp block_text(%MDEx.ListItem{nodes: nodes}) do
    nodes
    |> Enum.map(&block_text/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp block_text(%MDEx.CodeBlock{literal: literal}), do: String.trim_trailing(literal)

  defp block_text(%MDEx.BlockQuote{nodes: nodes}) do
    nodes
    |> Enum.map(&block_text/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n\n")
  end

  defp block_text(%{nodes: nodes}) do
    nodes
    |> Enum.map_join(&inline_text/1)
    |> String.trim()
  end

  defp block_text(_node), do: ""

  defp inline_text(%MDEx.Text{literal: literal}), do: literal
  defp inline_text(%MDEx.Code{literal: literal}), do: literal
  defp inline_text(%MDEx.SoftBreak{}), do: " "
  defp inline_text(%MDEx.LineBreak{}), do: "\n"

  # A link whose text equals its URL (autolink) stays bare; otherwise the
  # target is appended in parentheses so no information is lost.
  defp inline_text(%MDEx.Link{url: url, nodes: nodes}) do
    case Enum.map_join(nodes, &inline_text/1) do
      "" -> url
      ^url -> url
      text -> "#{text} (#{url})"
    end
  end

  defp inline_text(%{nodes: nodes}), do: Enum.map_join(nodes, &inline_text/1)
  defp inline_text(_node), do: ""
end
