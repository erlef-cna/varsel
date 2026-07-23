# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveViewTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [render_component: 2]

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

  describe "cwe_id_number/1 and capec_id_number/1" do
    test "parses the numeric id for catalog map lookups" do
      assert CveView.cwe_id_number("CWE-444") == 444
      assert CveView.capec_id_number("CAPEC-33") == 33
    end
  end

  describe "cwe_descriptions/1" do
    test "enumerates every English CWE problemType description, not just the first" do
      cna = %{
        "problemTypes" => [
          %{"descriptions" => [%{"lang" => "en", "type" => "CWE", "cweId" => "CWE-1"}]},
          %{"descriptions" => [%{"lang" => "en", "type" => "CWE", "cweId" => "CWE-2"}]}
        ]
      }

      assert Enum.map(CveView.cwe_descriptions(cna), & &1["cweId"]) == ["CWE-1", "CWE-2"]
      assert CveView.cwe_description(cna)["cweId"] == "CWE-1"
    end
  end

  describe "fix_boundary/1" do
    test "returns a concrete lessThan" do
      assert CveView.fix_boundary(%{"lessThan" => "1.4.0"}) == "1.4.0"
    end

    test "returns nil for a fully open range" do
      assert CveView.fix_boundary(%{"lessThan" => "*"}) == nil
    end

    test "walks changes[] for the lowest unaffected boundary within an open range" do
      version = %{
        "versionType" => "semver",
        "lessThan" => "*",
        "changes" => [
          %{"at" => "1.4.9", "status" => "unaffected"},
          %{"at" => "1.5.8", "status" => "unaffected"}
        ]
      }

      assert CveView.fix_boundary(version) == "1.4.9"
    end

    test "picks the lowest boundary by PARSED version, not array order (semver)" do
      version = %{
        "versionType" => "semver",
        "lessThan" => "*",
        "changes" => [
          %{"at" => "3.5.39", "status" => "unaffected"},
          %{"at" => "1.5.8", "status" => "unaffected"},
          %{"at" => "2.0.0", "status" => "unaffected"}
        ]
      }

      assert CveView.fix_boundary(version) == "1.5.8"
    end

    test "picks the lowest OTP release tag by parsed version, deliberately shuffled — CVE-2098-0002 shape" do
      version = %{
        "versionType" => "otp",
        "lessThan" => "*",
        "changes" => [
          %{"at" => "28.0.3", "status" => "unaffected"},
          %{"at" => "27.3.4.3", "status" => "unaffected"},
          %{"at" => "26.2.5.15", "status" => "unaffected"}
        ]
      }

      assert CveView.fix_boundary(version) == "26.2.5.15"
    end

    test "ignores affected-status changes when ranking the fix boundary" do
      version = %{
        "versionType" => "semver",
        "lessThan" => "*",
        "changes" => [
          %{"at" => "1.0.0", "status" => "affected"},
          %{"at" => "2.5.0", "status" => "unaffected"},
          %{"at" => "1.9.0", "status" => "unaffected"}
        ]
      }

      assert CveView.fix_boundary(version) == "1.9.0"
    end

    test "falls back to array order when boundaries don't parse (e.g. git shas)" do
      version = %{
        "versionType" => "git",
        "lessThan" => "*",
        "changes" => [
          %{"at" => "5f9af63eec4657a37663828d206517828cb9f288", "status" => "unaffected"},
          %{"at" => "d49efa2d4fa9e6f7ee658719cd76ffe7a33c2401", "status" => "unaffected"}
        ]
      }

      assert CveView.fix_boundary(version) == "5f9af63eec4657a37663828d206517828cb9f288"
    end
  end

  describe "branch_label/2" do
    test "semver-like versions render an X.Y series label from the fix boundary" do
      assert CveView.branch_label("1.5.8", "semver") == "1.5 series"
      assert CveView.branch_label("1.4.11", nil) == "1.4 series"
    end

    test "otp versionType renders a maint-N label, with or without the OTP- prefix" do
      assert CveView.branch_label("OTP-26.2.5.6", "otp") == "maint-26"
      assert CveView.branch_label("27.3.4", "otp") == "maint-27"
    end

    test "nil fix boundary yields no label" do
      assert CveView.branch_label(nil, "semver") == nil
    end
  end

  describe "sort_references/1" do
    test "advisory-tagged references sort first, stable within each group" do
      refs = [
        %{"url" => "a", "tags" => ["patch"]},
        %{"url" => "b", "tags" => ["vendor-advisory"]},
        %{"url" => "c", "tags" => ["mailing-list"]},
        %{"url" => "d", "tags" => ["vendor-advisory"]}
      ]

      assert Enum.map(CveView.sort_references(refs), & &1["url"]) == ["b", "d", "a", "c"]
    end

    test "patch-tagged references sort ahead of the rest, behind advisories" do
      refs = [
        %{"url" => "mailing-list", "tags" => ["mailing-list"]},
        %{"url" => "patch-1", "tags" => ["patch"]},
        %{"url" => "advisory", "tags" => ["vendor-advisory"]},
        %{"url" => "patch-2", "tags" => ["patch"]},
        %{"url" => "no-tags", "tags" => []}
      ]

      assert Enum.map(CveView.sort_references(refs), & &1["url"]) == [
               "advisory",
               "patch-1",
               "patch-2",
               "mailing-list",
               "no-tags"
             ]
    end
  end

  describe "registry_link/1" do
    test "hex and npm purls get a registry link" do
      assert CveView.registry_link(%{"packageURL" => "pkg:hex/bandit"}) ==
               {"Hex.pm", "https://hex.pm/packages/bandit"}

      assert CveView.registry_link(%{"packageURL" => "pkg:npm/left-pad"}) ==
               {"npm", "https://www.npmjs.com/package/left-pad"}
    end

    test "a github purl has no registry link (Repository covers it)" do
      assert CveView.registry_link(%{"packageURL" => "pkg:github/erlang/otp"}) == nil
    end

    test "an unlinkable purl type has no registry link" do
      assert CveView.registry_link(%{"vendor" => "Acme", "product" => "widget"}) == nil
    end
  end

  describe "id_name_chip/1" do
    test "renders the mono id, a separator, and the name, name span truncatable via name_class" do
      html =
        render_component(&CveView.id_name_chip/1, %{id: "CWE-444", name: "HTTP Request Smuggling"})

      assert html =~ "CWE-444"
      assert html =~ "·"
      assert html =~ "HTTP Request Smuggling"
    end

    test "a nil name renders only the bare id, no dangling separator" do
      html = render_component(&CveView.id_name_chip/1, %{id: "CWE-9999", name: nil})

      assert html =~ "CWE-9999"
      refute html =~ "·"
    end

    test "defaults to truncating the name (band chip usage)" do
      html =
        render_component(&CveView.id_name_chip/1, %{id: "CWE-444", name: "HTTP Request Smuggling"})

      assert html =~ "text-ellipsis"
      assert html =~ "whitespace-nowrap"
      refute html =~ "break-words"
    end

    test "truncate?={false} lets the full name wrap instead of ellipsizing (in-card usage)" do
      html =
        render_component(&CveView.id_name_chip/1, %{
          id: "CWE-78",
          name: "Improper Neutralization of Special Elements used in an OS Command",
          truncate?: false
        })

      assert html =~ "break-words"
      refute html =~ "text-ellipsis"
      refute html =~ "whitespace-nowrap"
      assert html =~ "Improper Neutralization of Special Elements used in an OS Command"
    end
  end

  describe "package_chip/1" do
    test "renders the mono pkg: label" do
      html =
        render_component(&CveView.package_chip/1, %{entry: %{"packageURL" => "pkg:hex/bandit"}})

      assert html =~ "pkg:hex/bandit"
    end
  end
end
