# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.SectionsTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.GitHubAdvisory.Sections

  describe "parse/1" do
    test "reads each level-3 section up to the next heading" do
      text = """
      ### Summary

      acme_lib passes user input into headers.

      #### A detail heading

      Stays in the summary.

      ### Workarounds

      Strip CRLF.
      """

      assert Sections.parse(text) == %{
               sections: %{
                 summary: "acme_lib passes user input into headers.\n\n#### A detail heading\n\nStays in the summary.",
                 workarounds: "Strip CRLF."
               },
               unmapped: []
             }
    end

    test "matches names case-insensitively and takes GitHub's PoC spelling" do
      text = "### SUMMARY\r\n\r\nShort.\r\n\r\n### PoC\r\n\r\ncurl -H 'x: \\r\\n'"

      assert %{sections: %{summary: "Short.", proof_of_concept: "curl -H 'x: \\r\\n'"}} =
               Sections.parse(text)
    end

    test "a heading inside a code block is body" do
      text = "### Details\n\n```\n### not a heading\n```"

      assert Sections.parse(text).sections == %{details: "```\n### not a heading\n```"}
    end

    test "text before the first heading, other headings and a repeated section are unmapped" do
      text = """
      Found by a scanner.

      ### Summary

      Short.

      ## Timeline

      March.

      ### Credits

      Alice.

      ### Summary

      Again.
      """

      assert Sections.parse(text) == %{
               sections: %{summary: "Short."},
               unmapped: [
                 %{heading: nil, body: "Found by a scanner."},
                 %{heading: "## Timeline", body: "March."},
                 %{heading: "### Credits", body: "Alice."},
                 %{heading: "### Summary", body: "Again."}
               ]
             }
    end

    test "a description with no section heading is all summary" do
      assert Sections.parse("Plain text.\n\n## Background\n\nMore.") == %{
               sections: %{summary: "Plain text.\n\n## Background\n\nMore."},
               unmapped: []
             }

      assert Sections.parse(nil) == %{sections: %{}, unmapped: []}
      assert Sections.parse("  ") == %{sections: %{}, unmapped: []}
    end
  end

  describe "splice/3" do
    test "replaces one section's body and keeps all other content" do
      text = "Intro.\n\n### summary\n\nOld.\n\n## Timeline\n\nMarch.\n\n### Solutions\n\nUpgrade."

      assert Sections.splice(text, :summary, "New.") ==
               "Intro.\n\n### summary\n\nNew.\n\n## Timeline\n\nMarch.\n\n### Solutions\n\nUpgrade."
    end

    test "puts a new section after the sections that precede it" do
      text = "### Summary\n\nShort.\n\n### Solutions\n\nUpgrade."

      assert Sections.splice(text, :details, "Deep.") ==
               "### Summary\n\nShort.\n\n### Details\n\nDeep.\n\n### Solutions\n\nUpgrade."

      assert Sections.splice("### Solutions\n\nUpgrade.", :summary, "Short.") ==
               "### Summary\n\nShort.\n\n### Solutions\n\nUpgrade."
    end

    test "gives a description with no section heading its summary heading" do
      assert Sections.splice("Plain text.", :solutions, "Upgrade.") ==
               "### Summary\n\nPlain text.\n\n### Solutions\n\nUpgrade."

      assert Sections.splice(nil, :details, "Deep.") == "### Details\n\nDeep."
    end
  end
end
