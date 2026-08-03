# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.ImportTest do
  @moduledoc """
  Reading a published CNA container back into case params: what transfers and
  what is deliberately dropped.
  """

  use ExUnit.Case, async: true

  alias Varsel.Cases.Case.Import

  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

  defp record(cna), do: %{"containers" => %{"cna" => cna}}

  defp prose(markdown) do
    [
      %{
        "lang" => "en",
        "value" => "flattened plain text",
        "supportingMedia" => [
          %{"base64" => false, "type" => "text/html", "value" => "<p>html</p>"},
          %{"base64" => false, "type" => "text/markdown", "value" => markdown}
        ]
      }
    ]
  end

  describe "case_params/1 — scalars" do
    test "takes the title, discovery and datePublic" do
      params =
        Import.case_params(
          record(%{
            "title" => "Information disclosure in acme_lib",
            "source" => %{"discovery" => "EXTERNAL"},
            "datePublic" => "2026-01-15T09:30:00.000Z"
          })
        )

      assert params.title == "Information disclosure in acme_lib"
      assert params.discovery == :external
      assert params.date_public == ~U[2026-01-15 09:30:00Z]
    end

    test "reads a date-only datePublic as midnight UTC" do
      params = Import.case_params(record(%{"datePublic" => "2026-01-15"}))

      assert params.date_public == ~U[2026-01-15 00:00:00Z]
    end

    test "omits keys the record has nothing for, leaving the action's defaults" do
      params = Import.case_params(record(%{"title" => "only a title"}))

      refute Map.has_key?(params, :discovery)
      refute Map.has_key?(params, :timeline)
      refute Map.has_key?(params, :date_public)
    end

    test "an unrecognized discovery value is dropped rather than guessed" do
      params = Import.case_params(record(%{"source" => %{"discovery" => "TELEPATHY"}}))

      refute Map.has_key?(params, :discovery)
    end

    test "handles a record with no CNA container at all" do
      assert Import.case_params(nil) == %{}
      assert Import.case_params(%{}) == %{}
    end

    test "takes the timeline" do
      params =
        Import.case_params(
          record(%{
            "timeline" => [
              %{"lang" => "en", "time" => "2026-01-10T00:00:00.000Z", "value" => "Reported"}
            ]
          })
        )

      assert [%{time: ~U[2026-01-10 00:00:00Z], value_md: "Reported"}] = params.timeline
    end
  end

  describe "case_params/1 — CVSS" do
    test "takes a v4 vector" do
      params =
        Import.case_params(record(%{"metrics" => [%{"cvssV4_0" => %{"vectorString" => @vector}}]}))

      assert params.cvss_v4 == @vector
    end

    test "leaves a v3-only record unscored — there is no faithful v3 to v4 path" do
      cna = %{
        "metrics" => [
          %{"cvssV3_1" => %{"vectorString" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
        ]
      }

      refute Map.has_key?(Import.case_params(record(cna)), :cvss_v4)
    end
  end

  describe "case_params/1 — prose" do
    test "takes the markdown source when the record carries one" do
      params =
        Import.case_params(
          record(%{
            "descriptions" => prose("A **bad** bug."),
            "workarounds" => prose("Turn it off."),
            "configurations" => prose("Only with `foo: true`."),
            "solutions" => prose("Upgrade.")
          })
        )

      assert params.description_md == "A **bad** bug."
      assert params.workarounds_md == "Turn it off."
      assert params.configurations_md == "Only with `foo: true`."
      assert params.solutions_md == "Upgrade."
    end

    test "falls back to the HTML when there is no markdown source" do
      cna = %{
        "descriptions" => [
          %{
            "lang" => "en",
            "value" => "A bad bug.",
            "supportingMedia" => [
              %{"base64" => false, "type" => "text/html", "value" => "<p>A <em>bad</em> bug.</p>"}
            ]
          }
        ]
      }

      assert Import.case_params(record(cna)).description_md == "<p>A <em>bad</em> bug.</p>"
    end

    test "falls back to the plain text when there is neither" do
      cna = %{"descriptions" => [%{"lang" => "en", "value" => "A bad bug."}]}

      assert Import.case_params(record(cna)).description_md == "A bad bug."
    end

    test "prefers markdown over HTML when both are present" do
      cna = %{
        "descriptions" => [
          %{
            "lang" => "en",
            "value" => "A bad bug.",
            "supportingMedia" => [
              %{"base64" => false, "type" => "text/html", "value" => "<p>A bad bug.</p>"},
              %{"base64" => false, "type" => "text/markdown", "value" => "A **bad** bug."}
            ]
          }
        ]
      }

      assert Import.case_params(record(cna)).description_md == "A **bad** bug."
    end

    test "strips the derived affected-versions sentence from the description" do
      markdown =
        "acme_lib leaks secrets.\n\nThis issue affects acme_lib: from 1.0.0 before 1.4.0."

      params = Import.case_params(record(%{"descriptions" => prose(markdown)}))

      assert params.description_md == "acme_lib leaks secrets."
    end

    test "strips the derived sentence from the plain-text fallback too" do
      cna = %{
        "descriptions" => [
          %{"value" => "acme leaks secrets.\n\nThis issue affects acme: from 1.0.0 before 1.4.0."}
        ]
      }

      assert Import.case_params(record(cna)).description_md == "acme leaks secrets."
    end

    # The tail arrives wrapped in <p>, so the paragraph match has to see
    # through the tag or the sentence gets published a second time.
    test "strips the derived sentence from the HTML fallback, keeping the rest" do
      cna = %{
        "descriptions" => [
          %{
            "value" => "x",
            "supportingMedia" => [
              %{
                "base64" => false,
                "type" => "text/html",
                "value" => "<ul>\n<li>one</li>\n<li>two</li>\n</ul>\n<p>This issue affects acme: before 1.4.0.</p>"
              }
            ]
          }
        ]
      }

      assert Import.case_params(record(cna)).description_md ==
               "<ul>\n<li>one</li>\n<li>two</li>\n</ul>"
    end

    test "a description that is only the derived sentence imports as nothing" do
      markdown = "This issue affects acme_lib: from 1.0.0 before 1.4.0."

      refute Map.has_key?(
               Import.case_params(record(%{"descriptions" => prose(markdown)})),
               :description_md
             )
    end

    test "a base64 supportingMedia is skipped in favour of the plain text" do
      cna = %{
        "descriptions" => [
          %{
            "lang" => "en",
            "value" => "A bad bug.",
            "supportingMedia" => [
              %{"base64" => true, "type" => "text/markdown", "value" => "QSBiYWQgYnVnLg=="}
            ]
          }
        ]
      }

      assert Import.case_params(record(cna)).description_md == "A bad bug."
    end
  end

  describe "child_params/1" do
    test "takes CWEs and CAPECs as numeric ids in order" do
      children =
        Import.child_params(
          record(%{
            "problemTypes" => [
              %{"descriptions" => [%{"cweId" => "CWE-200", "type" => "CWE"}]},
              %{"descriptions" => [%{"cweId" => "CWE-79", "type" => "CWE"}]}
            ],
            "impacts" => [%{"capecId" => "CAPEC-116"}, %{"capecId" => "CAPEC-63"}]
          })
        )

      assert [%{cwe_id: 200, position: 0}, %{cwe_id: 79, position: 1}] = children.weaknesses
      assert [%{capec_id: 116, position: 0}, %{capec_id: 63, position: 1}] = children.impacts
    end

    test "skips a non-numeric CWE (e.g. NVD-CWE-noinfo)" do
      children =
        Import.child_params(
          record(%{
            "problemTypes" => [
              %{"descriptions" => [%{"cweId" => "NVD-CWE-noinfo", "type" => "CWE"}]},
              %{"descriptions" => [%{"cweId" => "CWE-200", "type" => "CWE"}]}
            ]
          })
        )

      assert [%{cwe_id: 200}] = children.weaknesses
    end

    test "collapses a CWE repeated across problemTypes" do
      children =
        Import.child_params(
          record(%{
            "problemTypes" => [
              %{"descriptions" => [%{"cweId" => "CWE-200"}]},
              %{"descriptions" => [%{"cweId" => "CWE-200"}]}
            ]
          })
        )

      assert [%{cwe_id: 200, position: 0}] = children.weaknesses
    end

    test "splits credits back into name and organization" do
      children =
        Import.child_params(
          record(%{
            "credits" => [
              %{"lang" => "en", "type" => "finder", "value" => "Jonatan Männchen / EEF"},
              %{"lang" => "en", "type" => "remediation developer", "value" => "Someone Else"}
            ]
          })
        )

      assert [
               %{
                 name: "Jonatan Männchen",
                 organization: "EEF",
                 credit_type: :finder,
                 position: 0
               },
               %{
                 name: "Someone Else",
                 organization: nil,
                 credit_type: :remediation_developer,
                 position: 1
               }
             ] = children.credits
    end

    test "an unknown credit type falls back to finder rather than failing" do
      children =
        Import.child_params(record(%{"credits" => [%{"type" => "wizard", "value" => "A"}]}))

      assert [%{credit_type: :finder}] = children.credits
    end

    test "takes references with their tags, dropping the ones the renderer re-derives" do
      children =
        Import.child_params(
          record(%{
            "references" => [
              %{
                "tags" => ["vendor-advisory"],
                "url" => "https://github.com/acme/acme_lib/security/advisories/GHSA-x"
              },
              %{"tags" => ["related"], "url" => "https://cna.erlef.org/cves/CVE-2026-31337.html"},
              %{
                "tags" => ["related"],
                "url" => "https://osv.dev/vulnerability/EEF-CVE-2026-31337"
              },
              %{"tags" => ["patch"], "url" => "https://github.com/acme/acme_lib/commit/abc123"},
              %{"url" => "https://example.com/blog"}
            ]
          })
        )

      assert [
               %{
                 url: "https://github.com/acme/acme_lib/security/advisories/GHSA-x",
                 tags: ["vendor-advisory"],
                 position: 0
               },
               %{url: "https://example.com/blog", tags: [], position: 1}
             ] = children.references
    end
  end
end
