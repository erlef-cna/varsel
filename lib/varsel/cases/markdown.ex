# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Markdown do
  @moduledoc """
  Renders case markdown into the two representations CVE JSON description-like
  fields need: the plain-text `value` and the `supportingMedia` text/html
  value. Both derive from the same MDEx document, so they always agree.
  """

  alias Varsel.Markdown.CodeBlock
  alias Varsel.Markdown.Plaintext

  # `unsafe: true` lets authors embed literal HTML in their markdown; the
  # `sanitize` pass (ammonia, MDEx's conservative default allow-list) then
  # strips scripts, event handlers, and dangerous attributes/URLs before the
  # HTML is rendered with `raw/1`. See https://mdex.hexdocs.pm/safety.html.
  @options [
    extension: [table: true, autolink: true, strikethrough: true],
    render: [hardbreaks: false, unsafe: true],
    sanitize: MDEx.Document.default_sanitize_options()
  ]

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

  Highlighting is display-only: the supportingMedia HTML embedded in
  published CVE records stays free of site-specific `.l-*` token markup.

  The result is sanitized, so it is safe to render unescaped.
  """
  @spec to_display_html(String.t()) :: String.t()
  def to_display_html(markdown) when is_binary(markdown) do
    # The sanitizer drops `button`, so each block reserves its place with a
    # token and the button is spliced in afterwards. The token is random per
    # render, which is what keeps author markdown from naming one.
    placeholder =
      "varsel-copy-" <> Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

    # The highlighted markup goes through the same sanitize pass as the rest
    # of the document; MDEx's default allow-list admits the `pre`/`code`/`span`
    # classes Lumis emits.
    markdown
    |> MDEx.parse_document!(@options)
    |> MDEx.traverse_and_update(&CodeBlock.highlight(&1, {:deferred, placeholder}))
    |> MDEx.to_html!(@options)
    |> String.replace(placeholder, CodeBlock.deferred_button())
    |> String.trim()
  end

  @doc "Renders markdown to plain text (the descriptions[].value)."
  @spec to_plaintext(String.t()) :: String.t()
  def to_plaintext(markdown) when is_binary(markdown) do
    markdown
    |> MDEx.parse_document!(@options)
    |> Plaintext.render()
  end
end
