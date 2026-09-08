# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.ExportTest do
  use ExUnit.Case, async: true

  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Cases.Case.Calculations.Preview
  alias Varsel.Cases.CaseCredit
  alias Varsel.Cases.CaseCredit.Handle
  alias Varsel.Cases.CaseWeakness
  alias Varsel.Cases.GitHubAdvisory.Export
  alias Varsel.Cases.PackageChannel
  alias Varsel.Types.CVSS

  @vector "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"

  defp case_record(overrides) do
    {:ok, vector} = CVSS.cast_input(@vector, version: [:v4])

    struct!(
      Case,
      Map.merge(
        %{
          title: "Header injection in acme_lib",
          cvss_v4: vector,
          weaknesses: [%CaseWeakness{cwe_id: 113}, %CaseWeakness{cwe_id: 79}],
          credits: [
            %CaseCredit{
              name: "Alice",
              credit_type: :finder,
              handles: [%Handle{strategy: :github, username: "alice"}]
            },
            %CaseCredit{name: "Bob Nobody", credit_type: :reporter, handles: []}
          ],
          affected_packages: []
        },
        overrides
      )
    )
  end

  defp package(product, entries) do
    channels =
      Enum.map(entries, fn {channel, ranges} -> {%{channel | id: Ash.UUID.generate()}, ranges} end)

    cache =
      Map.new(channels, fn {channel, ranges} -> {channel.id, %{"github_ranges" => ranges}} end)

    %AffectedPackage{
      product: product,
      channels: Enum.map(channels, &elem(&1, 0)),
      derivation_cache: %{"channels" => cache}
    }
  end

  defp github_range(range, patched), do: %{"vulnerable_version_range" => range, "patched_versions" => patched}

  defp preview(cna), do: %Preview.Result{cve_record: %{"containers" => %{"cna" => cna}}}

  defp markdown(text) do
    [
      %{
        "lang" => "en",
        "value" => "plain",
        "supportingMedia" => [%{"base64" => false, "type" => "text/markdown", "value" => text}]
      }
    ]
  end

  test "the description is the whole advisory text with level 3 headings" do
    cna = %{
      "descriptions" => markdown("acme_lib passes user input into response headers."),
      "solutions" => markdown("Upgrade to 1.2.3."),
      "references" => [%{"url" => "https://example.com/fix", "name" => "The fix"}]
    }

    assert Export.description(case_record(%{preview: preview(cna)})) ==
             "### Summary\n\nacme_lib passes user input into response headers.\n\n" <>
               "### Solutions\n\nUpgrade to 1.2.3.\n\n" <>
               "### References\n\n* The fix: https://example.com/fix"

    assert %{body: %{"description" => "### Summary" <> _}} =
             Export.body(case_record(%{preview: preview(cna)}), [:description])
  end

  test "a case without prose has no description" do
    assert Export.description(case_record(%{preview: preview(%{})})) == nil
    assert Export.description(case_record(%{preview: nil})) == nil

    assert Export.body(case_record(%{preview: nil}), [:description]) == %{
             body: %{},
             skipped_credits: []
           }
  end

  test "vector/1 reads a case CVSS value" do
    assert Export.vector(%{vector: @vector}) == @vector
    assert Export.vector(nil) == nil
  end

  test "scalars and CWEs travel as GitHub names them" do
    assert Export.body(case_record(%{}), [:title, :cvss_v4, :weaknesses]) == %{
             body: %{
               "summary" => "Header injection in acme_lib",
               "cvss_vector_string" => @vector,
               "cwe_ids" => ["CWE-113", "CWE-79"]
             },
             skipped_credits: []
           }
  end

  test "the assigned CVE ID travels as cve_id" do
    assert %{body: %{"cve_id" => "CVE-2026-48858"}} =
             Export.body(case_record(%{cve_id: "CVE-2026-48858"}), [:cve_id])

    assert Export.body(case_record(%{cve_id: nil}), [:cve_id]) == %{
             body: %{},
             skipped_credits: []
           }
  end

  test "a value the case lacks is left out" do
    assert Export.body(case_record(%{title: nil, cvss_v4: nil}), [:title, :cvss_v4]) == %{
             body: %{},
             skipped_credits: []
           }
  end

  test "a person new to the advisory gets their weightiest role" do
    credits = [
      %CaseCredit{
        name: "Alice",
        credit_type: :finder,
        handles: [%Handle{strategy: :github, username: "alice"}]
      },
      %CaseCredit{
        name: "Alice",
        credit_type: :remediation_developer,
        handles: [%Handle{strategy: :github, username: "alice"}]
      }
    ]

    assert %{body: %{"credits" => [%{"login" => "alice", "type" => "remediation_developer"}]}} =
             Export.body(case_record(%{credits: credits}), [:credits])
  end

  test "credits keep the advisory's own, add ours by login, and report the ones without one" do
    advisory = %{
      "credits" => [
        %{"login" => "garazdawi", "type" => "reporter"},
        %{"login" => "ALICE", "type" => "analyst"}
      ]
    }

    assert %{
             body: %{
               "credits" => [
                 %{"login" => "garazdawi", "type" => "reporter"},
                 %{"login" => "ALICE", "type" => "analyst"}
               ]
             },
             skipped_credits: ["Bob Nobody"]
           } = Export.body(case_record(%{}), [:credits], advisory)

    assert %{body: %{"credits" => [%{"login" => "alice", "type" => "finder"}]}} =
             Export.body(case_record(%{}), [:credits])
  end

  test "affected packages are one entry per derived range, hex as erlang and the rest as other" do
    packages = [
      package("acme_lib", [
        {%PackageChannel{purl_type: "hex", name: "acme_lib"},
         [
           github_range(">= 1.0.0, < 1.2.3", ["1.2.3"]),
           github_range(">= 2.0.0, < 2.0.1", ["2.0.1"])
         ]},
        {%PackageChannel{purl_type: "github", namespace: "acme", name: "acme_lib"}, []}
      ]),
      package("OTP", [
        {%PackageChannel{purl_type: "otp", name: "inets", version_type: :otp},
         [github_range(">= 5.10", ["9.7.2", "9.6.2.3"])]}
      ])
    ]

    assert %{body: %{"vulnerabilities" => vulnerabilities}} =
             Export.body(case_record(%{affected_packages: packages}), [:affected])

    assert vulnerabilities == [
             %{
               "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
               "vulnerable_version_range" => ">= 1.0.0, < 1.2.3",
               "patched_versions" => "1.2.3"
             },
             %{
               "package" => %{"ecosystem" => "erlang", "name" => "acme_lib"},
               "vulnerable_version_range" => ">= 2.0.0, < 2.0.1",
               "patched_versions" => "2.0.1"
             },
             %{
               "package" => %{"ecosystem" => "other", "name" => "inets"},
               "vulnerable_version_range" => ">= 5.10",
               "patched_versions" => "9.7.2, 9.6.2.3"
             }
           ]
  end
end
