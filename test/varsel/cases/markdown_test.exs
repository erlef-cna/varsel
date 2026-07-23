# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.MarkdownTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.Markdown

  test "renders HTML" do
    assert Markdown.to_html("Hello `code` **bold**") ==
             "<p>Hello <code>code</code> <strong>bold</strong></p>"
  end

  test "display HTML highlights fenced code blocks; record HTML stays plain" do
    markdown = "```elixir\ndef foo, do: :bar\n```"

    assert Markdown.to_html(markdown) ==
             ~s(<pre><code class="language-elixir">def foo, do: :bar\n</code></pre>)

    display = Markdown.to_display_html(markdown)
    assert display =~ ~s(<pre class="lumis">)
    assert display =~ ~s(<span class="l-keyword-function">def</span>)
  end

  test "plain text strips inline formatting and keeps paragraph breaks" do
    markdown = """
    First paragraph with `inline code`.

    Second **bold** paragraph.
    """

    assert Markdown.to_plaintext(markdown) ==
             "First paragraph with inline code.\n\nSecond bold paragraph."
  end

  test "plain text keeps link targets" do
    assert Markdown.to_plaintext("See [the advisory](https://example.com/a).") ==
             "See the advisory (https://example.com/a)."

    assert Markdown.to_plaintext("See https://example.com/a.") == "See https://example.com/a."
  end

  test "plain text renders lists" do
    assert Markdown.to_plaintext("Options:\n\n* one\n* two") == "Options:\n\n* one\n* two"
  end

  test "sanitizes dangerous HTML but keeps safe author HTML" do
    for render <- [&Markdown.to_html/1, &Markdown.to_display_html/1] do
      html = render.("Hi <b>there</b> <script>alert('xss')</script>")
      assert html =~ "<b>there</b>"
      refute html =~ "<script"
      refute html =~ "alert"
    end

    # Event-handler attributes and javascript: URLs are stripped.
    img = "<img src=x onerror=" <> ~s("steal") <> ">"
    assert Markdown.to_html(img) == "<img src=" <> ~s("x") <> ">"

    js_scheme = "javascript" <> ":"
    js_link = "[x]" <> "(" <> js_scheme <> "alert" <> ")"
    refute Markdown.to_html(js_link) =~ js_scheme
  end
end
