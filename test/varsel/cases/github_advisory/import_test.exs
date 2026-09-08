# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.ImportTest do
  use ExUnit.Case, async: true

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Varsel.Cases.GitHubAdvisory.Import

  describe "case_params/1" do
    test "takes the summary, description, v4 vector and publication date" do
      assert Import.case_params(otp_advisory()) == %{
               title: "Unbounded resource use in inets",
               description_md: "The inets HTTP server allocates without limit.\n\nUpgrade.",
               cvss_v4: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
               date_public: ~U[2026-08-20 09:00:00Z]
             }
    end

    test "leaves out what the advisory lacks: a v3-only score, an unpublished date" do
      assert Import.case_params(hex_advisory()) == %{
               title: "Header injection in acme_lib",
               description_md: "acme_lib passes user input into response headers."
             }
    end

    test "treats blanks as absent" do
      assert Import.case_params(%{"summary" => "  ", "description" => ""}) == %{}
    end
  end

  test "blank_to_nil/1 keeps a string with content" do
    assert Import.blank_to_nil("text") == "text"
    assert Import.blank_to_nil(" \n") == nil
    assert Import.blank_to_nil(nil) == nil
    assert Import.blank_to_nil(42) == nil
  end

  describe "child_params/1 weaknesses" do
    test "reads the CWE ids once each, in order" do
      assert Import.child_params(hex_advisory()).weaknesses == [%{cwe_id: 113, position: 0}]
    end

    test "falls back to the cwes objects of a global entry" do
      advisory = %{
        "cwes" => [%{"cwe_id" => "CWE-79", "name" => "XSS"}, %{"cwe_id" => "not-a-cwe"}]
      }

      assert Import.child_params(advisory).weaknesses == [%{cwe_id: 79, position: 0}]
    end
  end

  describe "child_params/1 credits" do
    test "keeps accepted and pending credits with their login and role, drops declined ones" do
      assert Import.child_params(otp_advisory()).credits == [
               %{login: "garazdawi", credit_type: :reporter, position: 0},
               %{login: "Whaileee", credit_type: :remediation_reviewer, position: 1}
             ]
    end

    test "reads the plain credits of a global entry, whose roles it may not know" do
      advisory = %{"credits" => [%{"user" => %{"login" => "bob"}, "type" => "brand_new_role"}]}

      assert Import.child_params(advisory).credits == [
               %{login: "bob", credit_type: :other, position: 0}
             ]
    end
  end

  describe "child_params/1 affected" do
    test "an erlang entry becomes a package with a hex channel and no boundaries" do
      assert Import.child_params(hex_advisory()).affected == [
               %{
                 preset: nil,
                 applications: [],
                 attributes: %{
                   vendor: "acme",
                   product: "acme_lib",
                   repo_url: "https://github.com/acme/acme_lib"
                 },
                 channels: [%{purl_type: "hex", name: "acme_lib"}],
                 vulnerabilities: [
                   %{
                     ecosystem: "erlang",
                     name: "acme_lib",
                     vulnerable_version_range: ">= 1.0.0, < 1.2.3",
                     patched_versions: ["1.2.3"],
                     position: 0
                   }
                 ]
               }
             ]
    end

    test "an erlang/otp advisory goes through the OTP preset with its applications" do
      assert [%{preset: :otp, applications: ["inets"], channels: [], attributes: %{}} = package] =
               Import.child_params(otp_advisory()).affected

      assert Enum.map(
               package.vulnerabilities,
               &{&1.ecosystem, &1.name, &1.vulnerable_version_range}
             ) == [
               {nil, "OTP", ">= 17.0"},
               {"otp", "inets", ">= 5.10"}
             ]
    end

    test "an elixir-lang/elixir advisory names its applications from entries outside the erlang ecosystem" do
      advisory =
        hex_advisory()
        |> Map.put(
          "html_url",
          "https://github.com/elixir-lang/elixir/security/advisories/GHSA-2cfg-hjmp-qrvw"
        )
        |> Map.put("vulnerabilities", [
          %{
            "package" => %{"ecosystem" => "erlang", "name" => "elixir"},
            "vulnerable_version_range" => "< 1.18"
          },
          %{
            "package" => %{"ecosystem" => "elixir", "name" => "mix"},
            "vulnerable_version_range" => "< 1.18"
          }
        ])

      assert [%{preset: :elixir, applications: ["mix"], channels: [], attributes: %{}}] =
               Import.child_params(advisory).affected
    end

    test "a gleam-lang/gleam advisory names no applications" do
      advisory =
        hex_advisory()
        |> Map.put(
          "html_url",
          "https://github.com/gleam-lang/gleam/security/advisories/GHSA-2cfg-hjmp-qrvw"
        )
        |> Map.put("vulnerabilities", [
          %{
            "package" => %{"ecosystem" => "gleam", "name" => "gleam_stdlib"},
            "vulnerable_version_range" => "< 1.0"
          }
        ])

      assert [
               %{
                 preset: :gleam,
                 applications: [],
                 channels: [],
                 vulnerabilities: [%{name: "gleam_stdlib"}]
               }
             ] =
               Import.child_params(advisory).affected
    end

    test "an entry from an unknown ecosystem is a package with no channel" do
      advisory =
        Map.put(hex_advisory(), "vulnerabilities", [
          %{
            "package" => %{"ecosystem" => "npm", "name" => "acme-js"},
            "vulnerable_version_range" => "< 2"
          }
        ])

      assert [%{preset: nil, channels: [], attributes: %{vendor: "acme", product: "acme-js"}}] =
               Import.child_params(advisory).affected
    end

    test "an entry without a package name is skipped" do
      advisory =
        Map.put(hex_advisory(), "vulnerabilities", [
          %{"package" => %{"ecosystem" => "erlang", "name" => nil}}
        ])

      assert Import.child_params(advisory).affected == []
    end
  end
end
