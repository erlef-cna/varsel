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
end
