# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveViewTest do
  use ExUnit.Case, async: true

  alias VarselWeb.CveView

  describe "package_link/1" do
    test "maps hex, npm, github and oci purls to registry URLs" do
      assert CveView.package_link(%{"packageURL" => "pkg:hex/ash"}) ==
               {"pkg:hex/ash", "https://hex.pm/packages/ash"}

      assert CveView.package_link(%{"packageURL" => "pkg:npm/%40scope/pkg"}) ==
               {"pkg:npm/@scope/pkg", "https://www.npmjs.com/package/@scope/pkg"}

      assert CveView.package_link(%{"packageURL" => "pkg:github/ash-project/ash"}) ==
               {"pkg:github/ash-project/ash", "https://github.com/ash-project/ash"}
    end

    test "strips purl qualifiers" do
      assert {"pkg:hex/ash", "https://hex.pm/packages/ash"} =
               CveView.package_link(%{
                 "packageURL" => "pkg:hex/ash?repository_url=https://repo.hex.pm"
               })
    end

    test "falls back to vendor / product without a packageURL" do
      assert CveView.package_link(%{"vendor" => "Acme", "product" => "widget"}) ==
               {"Acme / widget", nil}
    end
  end

  describe "version_link/3" do
    test "special-cases wildcard and initial versions" do
      assert CveView.version_link("*", "semver", %{}) == {"no fix available", nil}
      assert CveView.version_link("0", "semver", %{}) == {"initial", nil}
    end

    test "links hex semver versions to hex.pm" do
      assert CveView.version_link("1.2.3", "semver", %{"packageURL" => "pkg:hex/ash"}) ==
               {"1.2.3", "https://hex.pm/packages/ash/1.2.3"}
    end

    test "links git versions to a github tree, truncating the sha label" do
      sha = "07b8f441ca711f9812fad9e9115bab3c3aa92f79"

      assert {"07b8f441ca", url} =
               CveView.version_link(sha, "git", %{"repo" => "https://github.com/erlang/otp"})

      assert url == "https://github.com/erlang/otp/tree/#{sha}"
    end

    test "links otp versions to the erlang.org patch page" do
      assert CveView.version_link("28.0.1", "otp", %{"packageName" => "erlang/otp"}) ==
               {"28.0.1", "https://www.erlang.org/patches/otp-28.0.1"}
    end
  end

  describe "best_cvss/1 and severity" do
    test "prefers v4.0 over v3.1" do
      cna = %{
        "metrics" => [
          %{"cvssV3_1" => %{"baseScore" => 5.0}},
          %{
            "cvssV4_0" => %{
              "baseScore" => 7.1,
              "baseSeverity" => "HIGH",
              "vectorString" => "CVSS:4.0/AV:N"
            }
          }
        ]
      }

      cvss = CveView.best_cvss(cna)
      assert cvss["version"] == "4.0"
      assert cvss["baseScore"] == 7.1
      assert CveView.cvss_calculator_url(cvss) =~ "cvss-v4-calculator"
    end

    test "returns nil when there are no metrics" do
      assert CveView.best_cvss(%{}) == nil
    end
  end

  describe "link_commit_shas/2" do
    test "links bare 40-hex shas to the repo's commit url" do
      refs = [
        %{
          "url" => "https://github.com/erlang/otp/commit/5a55feec10c9b69189d56723d8f237afa58d5d4f"
        }
      ]

      html = "Fixed in 5a55feec10c9b69189d56723d8f237afa58d5d4f now."

      out = html |> CveView.link_commit_shas(refs) |> Phoenix.HTML.safe_to_string()

      assert out =~
               ~s(href="https://github.com/erlang/otp/commit/5a55feec10c9b69189d56723d8f237afa58d5d4f")

      assert out =~ "5a55feec10</code>"
    end

    test "leaves content untouched when no commit reference exists" do
      html = "Fixed in 5a55feec10c9b69189d56723d8f237afa58d5d4f."
      out = html |> CveView.link_commit_shas([]) |> Phoenix.HTML.safe_to_string()
      refute out =~ "<a"
    end
  end

  describe "tag helpers" do
    test "humanizes and classifies tags and credits" do
      assert CveView.humanize_tag("unsupported-when-assigned") == "Unsupported when assigned"
      assert CveView.cna_tag_class("disputed") == "badge-warning"
      assert CveView.ref_tag_class("exploit") == "badge-error"
      assert CveView.humanize_credit("remediation_developer") == "Remediation developer"
    end
  end

  describe "cwe / capec urls" do
    test "builds mitre definition urls" do
      assert CveView.cwe_url("CWE-22") == "https://cwe.mitre.org/data/definitions/22.html"
      assert CveView.capec_url("CAPEC-180") == "https://capec.mitre.org/data/definitions/180.html"
    end
  end
end
