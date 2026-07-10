# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.CVE.OsvConverterTest do
  use ExUnit.Case, async: true

  alias CveManagement.CVE.OsvConverter

  @cve_id "CVE-2025-48042"

  @hex_affected %{
    "collectionURL" => "https://repo.hex.pm",
    "cpes" => ["cpe:2.3:a:ash-project:ash:*:*:*:*:*:*:*:*"],
    "defaultStatus" => "unaffected",
    "packageName" => "ash",
    "packageURL" => "pkg:hex/ash",
    "product" => "ash",
    "repo" => "https://github.com/ash-project/ash",
    "vendor" => "ash-project",
    "versions" => [
      %{
        "lessThan" => "3.5.39",
        "status" => "affected",
        "version" => "0",
        "versionType" => "semver"
      }
    ]
  }

  @git_affected %{
    "collectionURL" => "https://github.com",
    "defaultStatus" => "unaffected",
    "packageName" => "ash-project/ash",
    "packageURL" => "pkg:github/ash-project/ash",
    "product" => "ash",
    "repo" => "https://github.com/ash-project/ash",
    "vendor" => "ash-project",
    "versions" => [
      %{
        "lessThan" => "5d1b6a5d00771fd468a509778637527b5218be9a",
        "status" => "affected",
        "version" => "0",
        "versionType" => "git"
      }
    ]
  }

  @cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.2",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2025-09-07T16:01:01.470Z",
      "dateUpdated" => "2026-05-27T15:40:15.857Z"
    },
    "containers" => %{
      "cna" => %{
        "title" => "Before action hooks may execute despite a request being forbidden",
        "descriptions" => [
          %{
            "lang" => "en",
            "value" => "Incorrect Authorization vulnerability in ash-project ash."
          }
        ],
        "affected" => [@hex_affected, @git_affected],
        "credits" => [
          %{"lang" => "en", "type" => "remediation developer", "value" => "Zach Daniel"},
          %{"lang" => "en", "type" => "analyst", "value" => "Jonatan Männchen / EEF"}
        ],
        "impacts" => [%{"capecId" => "CAPEC-180"}],
        "metrics" => [
          %{
            "cvssV4_0" => %{
              "vectorString" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N",
              "version" => "4.0"
            },
            "format" => "CVSS"
          }
        ],
        "problemTypes" => [
          %{"descriptions" => [%{"cweId" => "CWE-863", "lang" => "en", "type" => "CWE"}]}
        ],
        "references" => [
          %{
            "tags" => ["vendor-advisory"],
            "url" => "https://github.com/ash-project/ash/security/advisories/GHSA-jj4j-x5ww-cwh9"
          },
          %{"tags" => ["related"], "url" => "https://cna.erlef.org/cves/CVE-2025-48042.html"},
          %{"tags" => ["related"], "url" => "https://osv.dev/vulnerability/EEF-CVE-2025-48042"},
          %{
            "tags" => ["patch"],
            "url" => "https://github.com/ash-project/ash/commit/5d1b6a5d00771fd468a509778637527b5218be9a"
          }
        ]
      }
    }
  }

  defp put_cna(cve_json, key, value), do: put_in(cve_json, ["containers", "cna", key], value)

  describe "convert/1" do
    test "converts a full CVE record" do
      assert {:ok, osv} = OsvConverter.convert(@cve_json)

      assert osv["schema_version"] == "1.7.3"
      assert osv["id"] == "EEF-#{@cve_id}"
      assert osv["published"] == "2025-09-07T16:01:01.470Z"
      assert osv["aliases"] == ["GHSA-jj4j-x5ww-cwh9", @cve_id]
      assert osv["upstream"] == []
      assert osv["related"] == []
      assert osv["summary"] == "Before action hooks may execute despite a request being forbidden"

      assert osv["details"] ==
               "## Summary\n\nIncorrect Authorization vulnerability in ash-project ash."

      assert osv["severity"] == [
               %{
                 "type" => "CVSS_V4",
                 "score" => "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N"
               }
             ]

      assert osv["credits"] == [
               %{"name" => "Zach Daniel", "type" => "REMEDIATION_DEVELOPER"},
               %{"name" => "Jonatan Männchen / EEF", "type" => "ANALYST"}
             ]

      assert osv["database_specific"] == %{
               "cwe_ids" => ["CWE-863"],
               "capec_ids" => ["CAPEC-180"],
               "cpe_ids" => ["cpe:2.3:a:ash-project:ash:*:*:*:*:*:*:*:*"]
             }

      # no modified timestamp — owned by the sync flow
      refute Map.has_key?(osv, "modified")
    end

    test "converts hex and git affected entries" do
      assert {:ok, osv} = OsvConverter.convert(@cve_json)

      assert [hex_entry, git_entry] = osv["affected"]

      assert hex_entry == %{
               "package" => %{"ecosystem" => "Hex", "name" => "ash", "purl" => "pkg:hex/ash"},
               "ranges" => [
                 %{
                   "type" => "SEMVER",
                   "events" => [%{"introduced" => "0"}, %{"fixed" => "3.5.39"}]
                 }
               ]
             }

      # hex versions are enumerated separately
      refute Map.has_key?(hex_entry, "versions")

      assert git_entry == %{
               "ranges" => [
                 %{
                   "type" => "GIT",
                   "repo" => "https://github.com/ash-project/ash",
                   "events" => [
                     %{"introduced" => "0"},
                     %{"fixed" => "5d1b6a5d00771fd468a509778637527b5218be9a"}
                   ]
                 }
               ]
             }
    end

    test "maps references and adds hex package references, dropping osv.dev" do
      assert {:ok, osv} = OsvConverter.convert(@cve_json)

      assert osv["references"] == [
               %{
                 "type" => "ADVISORY",
                 "url" => "https://github.com/ash-project/ash/security/advisories/GHSA-jj4j-x5ww-cwh9"
               },
               %{"type" => "WEB", "url" => "https://cna.erlef.org/cves/CVE-2025-48042.html"},
               %{
                 "type" => "FIX",
                 "url" => "https://github.com/ash-project/ash/commit/5d1b6a5d00771fd468a509778637527b5218be9a"
               },
               %{"type" => "PACKAGE", "url" => "https://hex.pm/packages/ash"}
             ]
    end

    test "skips records that are not published at MITRE" do
      cve_json = put_in(@cve_json, ["cveMetadata", "state"], "REJECTED")
      assert {:skip, reason} = OsvConverter.convert(cve_json)
      assert reason =~ "not published"
    end

    test "skips records without datePublished" do
      {_, cve_json} = pop_in(@cve_json, ["cveMetadata", "datePublished"])
      assert {:skip, reason} = OsvConverter.convert(cve_json)
      assert reason =~ "datePublished"
    end

    test "skips records without hex, npm, or git packages" do
      cve_json =
        put_cna(@cve_json, "affected", [
          %{"vendor" => "Acme", "product" => "widget", "defaultStatus" => "unknown"}
        ])

      assert {:skip, reason} = OsvConverter.convert(cve_json)
      assert reason =~ "No hex, npm, or git repositories"
    end

    test "accepts hex packages identified only by their package URL" do
      affected = @hex_affected |> Map.delete("collectionURL") |> Map.delete("packageName")
      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"package" => %{"ecosystem" => "Hex", "name" => "ash"}}] = osv["affected"]
    end

    test "ignores namespaced (private organization) hex purls" do
      affected =
        @hex_affected
        |> Map.delete("collectionURL")
        |> Map.delete("packageName")
        |> Map.put("packageURL", "pkg:hex/acme/ash")

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:skip, _reason} = OsvConverter.convert(cve_json)
    end

    test "converts npm affected entries" do
      affected = %{
        "collectionURL" => "https://registry.npmjs.org",
        "packageName" => "phoenix",
        "packageURL" => "pkg:npm/phoenix",
        "defaultStatus" => "unaffected",
        "versions" => [
          %{
            "lessThan" => "1.7.14",
            "status" => "affected",
            "version" => "0",
            "versionType" => "semver"
          }
        ]
      }

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [
               %{
                 "package" => %{
                   "ecosystem" => "npm",
                   "name" => "phoenix",
                   "purl" => "pkg:npm/phoenix"
                 },
                 "ranges" => [
                   %{
                     "type" => "SEMVER",
                     "events" => [%{"introduced" => "0"}, %{"fixed" => "1.7.14"}]
                   }
                 ]
               }
             ] = osv["affected"]

      assert %{"type" => "PACKAGE", "url" => "https://www.npmjs.com/package/phoenix"} in osv[
               "references"
             ]
    end

    test "accepts scoped npm packages identified only by their package URL" do
      affected = %{
        "packageURL" => "pkg:npm/%40scope/pkg",
        "defaultStatus" => "affected"
      }

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [
               %{
                 "package" => %{
                   "ecosystem" => "npm",
                   "name" => "@scope/pkg",
                   "purl" => "pkg:npm/%40scope/pkg"
                 }
               }
             ] = osv["affected"]
    end

    test "orders affected entries as hex, npm, git" do
      npm_affected = %{
        "collectionURL" => "https://registry.npmjs.org",
        "packageName" => "phoenix",
        "packageURL" => "pkg:npm/phoenix",
        "defaultStatus" => "affected"
      }

      cve_json = put_cna(@cve_json, "affected", [npm_affected, @git_affected, @hex_affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [
               %{"package" => %{"ecosystem" => "Hex"}},
               %{"package" => %{"ecosystem" => "npm"}},
               %{"ranges" => [%{"type" => "GIT"}]}
             ] = osv["affected"]
    end

    test "falls back to the first description line when there is no title" do
      cve_json =
        @cve_json
        |> put_cna("title", nil)
        |> put_cna("descriptions", [
          %{"lang" => "en", "value" => "  First line.\nSecond line."}
        ])

      assert {:ok, osv} = OsvConverter.convert(cve_json)
      assert osv["summary"] == "First line."
    end

    test "renders workaround and configuration sections with markdown escaping" do
      cve_json =
        @cve_json
        |> put_cna("descriptions", [%{"lang" => "en", "value" => "Uses `zip:unzip/1`."}])
        |> put_cna("workarounds", [%{"lang" => "en", "value" => "Check with zip:list_dir/1."}])
        |> put_cna("configurations", [%{"lang" => "en", "value" => "Only with [memory] off."}])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert osv["details"] ==
               "## Summary\n\nUses \\`zip:unzip/1\\`." <>
                 "\n\n## Workaround\n\nCheck with zip:list\\_dir/1." <>
                 "\n\n## Configuration\n\nOnly with \\[memory\\] off."
    end

    test "emits an all-versions range when defaultStatus is affected without versions" do
      affected =
        @hex_affected
        |> Map.put("defaultStatus", "affected")
        |> Map.delete("versions")
        |> Map.delete("repo")

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"ranges" => [%{"type" => "SEMVER", "events" => [%{"introduced" => "0"}]}]}] =
               osv["affected"]
    end

    test "converts lessThanOrEqual to last_affected and unaffected versions to fixed" do
      affected =
        Map.put(@hex_affected, "versions", [
          %{
            "version" => "1.0.0",
            "lessThanOrEqual" => "1.5.0",
            "status" => "affected",
            "versionType" => "semver"
          },
          %{"version" => "2.0.0", "status" => "unaffected", "versionType" => "semver"}
        ])

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"ranges" => ranges}] = osv["affected"]

      assert ranges == [
               %{
                 "type" => "SEMVER",
                 "events" => [%{"introduced" => "1.0.0"}, %{"last_affected" => "1.5.0"}]
               },
               # a fix-only entry gets an introduced event to satisfy the OSV schema
               %{"type" => "SEMVER", "events" => [%{"introduced" => "0"}, %{"fixed" => "2.0.0"}]}
             ]
    end

    test "drops last_affected when a fixed event lands in the same range" do
      affected =
        Map.put(@git_affected, "versions", [
          %{
            "version" => "aaa",
            "lessThanOrEqual" => "bbb",
            "status" => "affected",
            "versionType" => "git"
          },
          %{
            "version" => "ccc",
            "lessThan" => "ddd",
            "status" => "affected",
            "versionType" => "git"
          }
        ])

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"ranges" => [%{"type" => "GIT", "events" => events}]}] = osv["affected"]

      # fixed and last_affected are mutually exclusive within a range
      assert events == [
               %{"introduced" => "aaa"},
               %{"introduced" => "ccc"},
               %{"fixed" => "ddd"}
             ]
    end

    test "assumes GMT for CVE timestamps without an offset" do
      cve_json = put_in(@cve_json, ["cveMetadata", "datePublished"], "2025-09-07T16:01:01")

      assert {:ok, osv} = OsvConverter.convert(cve_json)
      assert osv["published"] == "2025-09-07T16:01:01Z"
    end

    test "uses only the first English description for the details summary" do
      cve_json =
        put_cna(@cve_json, "descriptions", [
          %{"lang" => "en", "value" => "Primary description."},
          %{"lang" => "en", "value" => "Auto-generated variant."}
        ])

      assert {:ok, osv} = OsvConverter.convert(cve_json)
      assert osv["details"] == "## Summary\n\nPrimary description."
    end

    test "strips purl prefixes from version boundaries" do
      affected =
        Map.put(@hex_affected, "versions", [
          %{
            "version" => "pkg:hex/ash@1.0.0",
            "lessThan" => "pkg:hex/ash@2.0.0",
            "status" => "affected",
            "versionType" => "semver"
          }
        ])

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"ranges" => [%{"events" => [%{"introduced" => "1.0.0"}, %{"fixed" => "2.0.0"}]}]}] =
               osv["affected"]
    end

    test "converts change entries to additional fix events" do
      affected =
        Map.put(@git_affected, "versions", [
          %{
            "version" => "07b8f441ca711f9812fad9e9115bab3c3aa92f79",
            "status" => "affected",
            "versionType" => "git",
            "changes" => [
              %{"at" => "d9454dbccbaaad4b8796095c8e653b71b066dfaf", "status" => "unaffected"},
              %{"at" => "9b7b5431260e05a16eec3ecd530a232d0995d932", "status" => "unaffected"}
            ]
          }
        ])

      cve_json = put_cna(@cve_json, "affected", [affected])

      assert {:ok, osv} = OsvConverter.convert(cve_json)

      assert [%{"ranges" => [%{"type" => "GIT", "events" => events}]}] = osv["affected"]

      assert events == [
               %{"introduced" => "07b8f441ca711f9812fad9e9115bab3c3aa92f79"},
               %{"fixed" => "d9454dbccbaaad4b8796095c8e653b71b066dfaf"},
               %{"fixed" => "9b7b5431260e05a16eec3ecd530a232d0995d932"}
             ]
    end
  end

  describe "enumerate_affected_versions/2" do
    test "enumerates, filters, and sorts affected hex versions" do
      {:ok, osv} = OsvConverter.convert(@cve_json)

      fetch = fn "ash" -> {:ok, ["3.5.39", "0.1.0", "3.5.38", "10.0.0", "3.0.0"]} end

      assert {:ok, osv} = OsvConverter.enumerate_affected_versions(osv, fetch)

      assert [%{"versions" => ["0.1.0", "3.0.0", "3.5.38"]}, git_entry] = osv["affected"]
      refute Map.has_key?(git_entry, "versions")
    end

    test "propagates lookup errors" do
      {:ok, osv} = OsvConverter.convert(@cve_json)

      fetch = fn "ash" -> {:error, "hex.pm returned 500 for ash"} end

      assert {:error, reason} = OsvConverter.enumerate_affected_versions(osv, fetch)
      assert reason =~ "ash"
    end
  end

  describe "filter_affected_versions/2" do
    test "keeps versions inside any semver range" do
      ranges = [
        %{
          "type" => "SEMVER",
          "events" => [%{"introduced" => "1.0.0"}, %{"fixed" => "1.2.0"}]
        },
        %{
          "type" => "SEMVER",
          "events" => [%{"introduced" => "2.0.0"}, %{"last_affected" => "2.1.0"}]
        }
      ]

      versions = ["0.9.0", "1.0.0", "1.1.9", "1.2.0", "2.0.0", "2.1.0", "2.2.0"]

      assert OsvConverter.filter_affected_versions(versions, ranges) ==
               ["1.0.0", "1.1.9", "2.0.0", "2.1.0"]
    end

    test "includes all versions when there is no semver range" do
      ranges = [%{"type" => "GIT", "events" => [%{"introduced" => "0"}]}]

      assert OsvConverter.filter_affected_versions(["1.0.0", "2.0.0"], ranges) ==
               ["1.0.0", "2.0.0"]
    end
  end

  describe "content_hash/1" do
    test "ignores the modified timestamp but tracks content" do
      {:ok, osv} = OsvConverter.convert(@cve_json)

      hash = OsvConverter.content_hash(osv)

      assert OsvConverter.content_hash(Map.put(osv, "modified", "2026-01-01T00:00:00Z")) == hash
      refute OsvConverter.content_hash(Map.put(osv, "summary", "Changed")) == hash
    end
  end
end
