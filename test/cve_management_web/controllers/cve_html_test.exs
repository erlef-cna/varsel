# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveHtmlTest do
  use CveManagementWeb.ConnCase, async: false

  alias CveManagement.CVE.CveRecord

  @cve_id "CVE-2025-48042"

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
          %{"lang" => "en", "value" => "Incorrect Authorization vulnerability in ash."}
        ],
        "affected" => [
          %{
            "collectionURL" => "https://repo.hex.pm",
            "packageName" => "ash",
            "packageURL" => "pkg:hex/ash",
            "defaultStatus" => "unaffected",
            "versions" => [
              %{
                "version" => "0",
                "lessThan" => "3.5.39",
                "status" => "affected",
                "versionType" => "semver"
              }
            ]
          }
        ],
        "problemTypes" => [
          %{
            "descriptions" => [
              %{
                "cweId" => "CWE-863",
                "description" => "Incorrect Authorization",
                "lang" => "en",
                "type" => "CWE"
              }
            ]
          }
        ],
        "impacts" => [
          %{
            "capecId" => "CAPEC-180",
            "descriptions" => [%{"lang" => "en", "value" => "Exploiting Access Control"}]
          }
        ],
        "metrics" => [
          %{
            "cvssV4_0" => %{
              "baseScore" => 7.1,
              "baseSeverity" => "HIGH",
              "vectorString" => "CVSS:4.0/AV:N/AC:L",
              "version" => "4.0"
            }
          }
        ],
        "credits" => [
          %{"lang" => "en", "type" => "remediation developer", "value" => "Zach Daniel"}
        ],
        "references" => [
          %{
            "tags" => ["vendor-advisory"],
            "url" => "https://github.com/ash-project/ash/security/advisories/GHSA-jj4j-x5ww-cwh9"
          }
        ]
      }
    }
  }

  defp publish(cve_json \\ @cve_json) do
    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  describe "GET /cves/:cve_id (HTML)" do
    test "renders the detail page for a published record", %{conn: conn} do
      publish()

      conn = get(conn, ~p"/cves/#{@cve_id}")
      body = html_response(conn, 200)

      assert body =~ @cve_id
      assert body =~ "Before action hooks may execute"
      assert body =~ "hex.pm/packages/ash"
      assert body =~ "cwe.mitre.org/data/definitions/863"
      assert body =~ "capec.mitre.org/data/definitions/180"
      assert body =~ "7.1"
      assert body =~ "GHSA-jj4j-x5ww-cwh9"
      assert body =~ "Zach Daniel"
      assert body =~ "osv.dev/vulnerability/EEF-#{@cve_id}"
    end

    test "returns 404 for an unknown id", %{conn: conn} do
      conn = get(conn, ~p"/cves/CVE-0000-00000")
      assert html_response(conn, 404)
    end
  end

  describe "GET /cves/:cve_id.json still serves the raw record" do
    test "returns the cve_json", %{conn: conn} do
      publish()

      conn = get(conn, "/cves/#{@cve_id}.json")
      assert json_response(conn, 200)["cveMetadata"]["cveId"] == @cve_id
    end
  end

  describe "GET /cves/index.json is not shadowed by the html route" do
    test "returns the machine-readable index", %{conn: conn} do
      publish()

      conn = get(conn, "/cves/index.json")
      [entry] = json_response(conn, 200)
      assert entry["id"] == @cve_id
    end
  end
end
