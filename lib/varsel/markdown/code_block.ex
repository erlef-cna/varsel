# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Markdown.CodeBlock do
  @moduledoc """
  Renders a fenced code block into the codebox treatment the site uses
  everywhere: Lumis syntax highlighting with a copy button on top.
  """

  alias VarselWeb.CoreComponents

  @languages Application.compile_env!(:varsel, :lumis_languages)

  @doc "The languages code blocks are highlighted in."
  @spec languages() :: [String.t()]
  def languages, do: @languages

  @doc """
  Replaces a `MDEx.CodeBlock` with its highlighted codebox, leaving every
  other node alone. A block Lumis cannot highlight is left alone too.

      MDEx.traverse_and_update(document, &CodeBlock.highlight/1)

  `button` says how the copy button is rendered:

    * `:live` for a page a LiveView is running on, which interprets its
      `phx-click`
    * `:dead` for a page served by a controller, where app.js binds it
    * `{:deferred, placeholder}` to leave a marker in its place, for a caller
      that sanitizes afterwards and substitutes `deferred_button/0` once the
      sanitizer has run
  """
  @spec highlight(MDEx.Document.md_node(), :live | :dead | {:deferred, String.t()}) ::
          MDEx.Document.md_node()
  def highlight(node, button \\ :live)

  # The literal keeps the newline that closed the fence, which Lumis would
  # render as one more, empty line.
  def highlight(%MDEx.CodeBlock{info: info, literal: literal} = block, button) do
    source = String.trim_trailing(literal, "\n")

    case Lumis.highlight(source, formatter: {:html_linked, language: language(info)}) do
      {:ok, html} ->
        %MDEx.HtmlBlock{literal: ~s(<div class="codebox">#{html}#{trailer(button)}</div>)}

      {:error, _reason} ->
        block
    end
  end

  def highlight(node, _button), do: node

  @doc """
  The copy button a `{:deferred, placeholder}` block left room for.
  """
  @spec deferred_button() :: String.t()
  def deferred_button, do: trailer(:live)

  defp trailer({:deferred, placeholder}), do: placeholder

  defp trailer(mode) when mode in [:live, :dead] do
    CoreComponents.component_to_html(&CoreComponents.code_copy_button/1, live?: mode == :live)
  end

  # Plain text is a name Lumis answers without loading anything.
  defp language(info) do
    case String.split(info, ~r/\s+/, parts: 2, trim: true) do
      [language | _] when language in @languages -> language
      _other -> "text"
    end
  end
end
