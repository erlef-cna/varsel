# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content.Page do
  @moduledoc """
  A static content page built by `Varsel.Content` (nimble_publisher).

  Comrak renders each heading with a clickable anchor permalink
  (`<h2><a class="anchor" id="slug"></a>Text</h2>`) via the `header_id_prefix`
  extension configured on the `Content` module. At build time we read those
  anchor ids back into a table of contents (`toc`) — the Phoenix equivalent of
  the Jekyll theme's `page_with_toc` layout. `toc` is a list of
  `%{level, id, text}`, empty when the page has no `##`/`###` headings.
  """

  @enforce_keys [:id, :title, :body]
  defstruct [:id, :title, :body, :description, toc: []]

  # Matches `<h2><a ... id="slug"></a>Heading text</h2>` (and h3).
  @heading_regex ~r{<h([23])><a[^>]*\bid="([^"]+)"[^>]*></a>(.*?)</h\1>}s

  def build(filename, attrs, body) do
    id = filename |> Path.basename() |> Path.rootname()

    struct!(__MODULE__, [id: id, body: body, toc: extract_toc(body)] ++ Map.to_list(attrs))
  end

  defp extract_toc(body) do
    @heading_regex
    |> Regex.scan(body)
    |> Enum.map(fn [_full, level, slug, inner] ->
      %{level: String.to_integer(level), id: slug, text: strip_tags(inner)}
    end)
  end

  defp strip_tags(html) do
    html
    |> String.replace(~r/<[^>]*>/, "")
    |> unescape_entities()
    |> String.trim()
  end

  # Comrak escapes heading text (e.g. `&amp;`); decode the handful that occur
  # so the table of contents reads cleanly.
  defp unescape_entities(text) do
    text
    |> String.replace("&amp;", "&")
    |> String.replace("&lt;", "<")
    |> String.replace("&gt;", ">")
    |> String.replace("&quot;", "\"")
    |> String.replace("&#39;", "'")
  end
end
