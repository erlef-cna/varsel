# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Markdown do
  @moduledoc """
  Renders case markdown into the two representations CVE JSON description-like
  fields need: the plain-text `value` and the `supportingMedia` text/html
  value. Both derive from the same MDEx document, so they always agree.
  """

  # `unsafe: true` lets authors embed literal HTML in their markdown; the
  # `sanitize` pass (ammonia, MDEx's conservative default allow-list) then
  # strips scripts, event handlers, and dangerous attributes/URLs before the
  # HTML is rendered with `raw/1`. See https://mdex.hexdocs.pm/safety.html.
  @options [
    extension: [table: true, autolink: true, strikethrough: true],
    render: [hardbreaks: false, unsafe: true],
    sanitize: MDEx.Document.default_sanitize_options()
  ]

  # Lumis highlighting is display-only: the supportingMedia HTML embedded in
  # published CVE records stays free of site-specific `.l-*` token markup.
  @display_options @options ++
                     [syntax_highlight: [engine: :lumis, opts: [formatter: :html_linked]]]

  @doc "Renders markdown to HTML (the supportingMedia text/html value)."
  @spec to_html(String.t()) :: String.t()
  def to_html(markdown) when is_binary(markdown) do
    markdown
    |> MDEx.to_html!(@options)
    |> String.trim()
  end

  @doc """
  Renders markdown to HTML for on-site display: `to_html/1` plus Lumis
  syntax highlighting of fenced code blocks (`.lumis` / `.l-*` classes,
  styled by the generated `assets/vendor/css/lumis.css`).
  """
  @spec to_display_html(String.t()) :: String.t()
  def to_display_html(markdown) when is_binary(markdown) do
    markdown
    |> MDEx.to_html!(@display_options)
    |> String.trim()
  end

  @doc "Renders markdown to plain text (the descriptions[].value)."
  @spec to_plaintext(String.t()) :: String.t()
  def to_plaintext(markdown) when is_binary(markdown) do
    document = MDEx.parse_document!(markdown, @options)

    document.nodes
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
