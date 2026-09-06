# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.CVE.AdvisoryTest do
  use ExUnit.Case, async: true

  alias Varsel.CVE.Advisory

  defp prose(markdown, plain \\ "plain") do
    [
      %{
        "lang" => "en",
        "value" => plain,
        "supportingMedia" => [
          %{"base64" => false, "type" => "text/html", "value" => "<p>html</p>"},
          %{"base64" => false, "type" => "text/markdown", "value" => markdown}
        ]
      }
    ]
  end

  defp cna do
    %{
      "descriptions" => prose("Sessions **outlive** logout."),
      "x_technicalAnalysis" => prose("The token is never revoked."),
      "x_proofOfConcept" => prose("1. Log out.\n2. Replay the cookie."),
      "impacts" => [
        %{
          "capecId" => "CAPEC-593",
          "descriptions" => [%{"lang" => "en", "value" => "CAPEC-593 Session Hijacking"}]
        },
        %{"capecId" => "CAPEC-21", "descriptions" => prose("Any logged-out session replays.")}
      ],
      "workarounds" => prose("Rotate the signing secret."),
      "configurations" => [%{"lang" => "en", "value" => "Only with [sessions] on."}],
      "solutions" => [%{"lang" => "de", "value" => "Nicht auf Englisch."}],
      "references" => [
        %{
          "url" => "https://example.com/advisory",
          "name" => "GHSA-xxxx",
          "tags" => ["vendor-advisory"]
        },
        %{"url" => "https://example.com/commit/abc"}
      ]
    }
  end

  test "renders every included section in a fixed order under its heading" do
    assert Advisory.render(cna(), Enum.reverse(Advisory.keys())) ==
             """
             ## Summary

             Sessions **outlive** logout.

             ## Details

             The token is never revoked.

             ## Proof of concept

             1. Log out.
             2. Replay the cookie.

             ## Impact

             Any logged-out session replays.

             ## Workarounds

             Rotate the signing secret.

             ## Configurations

             Only with \\[sessions\\] on.

             ## References

             * GHSA-xxxx: https://example.com/advisory
             * https://example.com/commit/abc\
             """
  end

  test "renders only the included sections" do
    assert Advisory.render(cna(), [:summary, :workarounds]) ==
             "## Summary\n\nSessions **outlive** logout.\n\n## Workarounds\n\nRotate the signing secret."
  end

  test "skips a section the record does not carry and a non-English entry" do
    assert Advisory.render(cna(), [:solutions]) == ""
    assert Advisory.render(%{}, Advisory.keys()) == ""
  end

  test "escapes the plain value only when there is no markdown source" do
    cna = %{"descriptions" => [%{"lang" => "en", "value" => "Uses `zip:unzip/1` and *ranges*."}]}

    assert Advisory.render(cna, [:summary]) ==
             "## Summary\n\nUses \\`zip:unzip/1\\` and \\*ranges\\*."
  end

  test "an impact that only restates its CAPEC label is not an impact paragraph" do
    cna = %{"impacts" => [hd(cna()["impacts"])]}

    assert Advisory.render(cna, [:impact]) == ""
  end
end
