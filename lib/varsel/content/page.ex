# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Content.Page do
  @moduledoc """
  A static content page built by `Varsel.Content` (nimble_publisher).

  Comrak renders each heading with an id on the tag and a clickable anchor
  permalink (`<h2 id="slug">Text<a class="anchor" href="#slug"></a></h2>`) via
  the `header_id_prefix` extension configured on the `Content` module. At build
  time we read those anchor ids back into a table of contents (`toc`) — the
  Phoenix equivalent of the Jekyll theme's `page_with_toc` layout. `toc` is a
  list of `%{level, id, text}`, empty when the page has no `##`/`###` headings.
  """

  alias VarselWeb.CoreComponents

  @enforce_keys [:id, :title, :body]
  defstruct [:id, :title, :body, :description, toc: []]

  # Matches `<h2 id="slug">Heading text<a ... class="anchor"></a></h2>` (and h3).
  @heading_regex ~r{<h([23])[^>]*\bid="([^"]+)"[^>]*>(.*?)</h\1>}s

  # Comrak renders a fenced block as `<pre><code …>…</code></pre>`.
  @code_block_regex ~r{<pre>(.*?</code>)</pre>}s

  def build(filename, attrs, body) do
    id = filename |> Path.basename() |> Path.rootname()
    body = add_copy_buttons(body)

    struct!(__MODULE__, [id: id, body: body, toc: extract_toc(body)] ++ Map.to_list(attrs))
  end

  # These pages are served by a controller, with no LiveView to interpret the
  # button's `phx-click`.
  defp add_copy_buttons(body) do
    button = CoreComponents.code_copy_button_html(live?: false)

    Regex.replace(@code_block_regex, body, fn _full, inner ->
      ~s(<div class="codebox"><pre>) <> inner <> "</pre>" <> button <> "</div>"
    end)
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
