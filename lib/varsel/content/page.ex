# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content.Page do
  @moduledoc """
  A static content page: the markdown under `priv/pages` compiled to the HTML
  the docs template renders, plus the table of contents beside it.
  """

  alias Varsel.Markdown.CodeBlock
  alias Varsel.Markdown.TableOfContents

  @enforce_keys [:id, :title, :body]
  defstruct [:id, :title, :body, :description, toc: []]

  @type t :: %__MODULE__{
          id: String.t(),
          title: String.t(),
          body: String.t(),
          description: String.t() | nil,
          toc: [TableOfContents.entry()]
        }

  # `header_id_prefix` gives every heading an id and a permalink anchor, which
  # the table of contents addresses. `block_directive` enables the `:::steps`
  # fences the process pages use. These pages are repo content, so
  # `unsafe: true` carries no sanitize pass.
  @options [
    extension: [
      table: true,
      autolink: true,
      strikethrough: true,
      block_directive: true,
      header_id_prefix: ""
    ],
    render: [hardbreaks: false, unsafe: true]
  ]

  @doc """
  Compiles one page's markdown source into a `t:t/0`.

  The attributes are a literal Elixir map above a `---` line, as
  `%{title: "…", description: "…"}`.
  """
  @spec build(String.t(), String.t()) :: t()
  def build(path, source) do
    {attrs, markdown} = split_attributes(path, source)

    document =
      markdown
      |> MDEx.parse_document!(@options)
      # Served by a controller, with no LiveView to interpret a `phx-click`.
      |> MDEx.traverse_and_update(&CodeBlock.highlight(&1, :dead))

    struct!(
      __MODULE__,
      [
        id: path |> Path.basename() |> Path.rootname(),
        body: MDEx.to_html!(document, @options),
        toc: TableOfContents.build(document)
      ] ++ Map.to_list(attrs)
    )
  end

  # Read as a term, so a page cannot run code at compile time.
  defp split_attributes(path, source) do
    with [attributes, markdown] <- String.split(source, ~r/\n-{3,}\n/, parts: 2),
         {:ok, quoted} <- Code.string_to_quoted(attributes),
         {:ok, attrs} <- literal_map(quoted) do
      {attrs, markdown}
    else
      _other -> raise "#{path}: expected a literal attribute map above a --- line"
    end
  end

  defp literal_map({:%{}, _meta, pairs}) do
    if Enum.all?(pairs, fn {key, value} -> is_atom(key) and is_binary(value) end),
      do: {:ok, Map.new(pairs)},
      else: :error
  end

  defp literal_map(_quoted), do: :error
end
