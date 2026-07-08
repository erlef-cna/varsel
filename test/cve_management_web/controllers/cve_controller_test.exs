# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CveControllerTest do
  use CveManagementWeb.ConnCase, async: false

  alias CveManagement.CVE.CveRecord

  @cve_id "CVE-2025-12345"
  @other_cve_id "CVE-2025-99999"

  @published_cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.2",
    "cveMetadata" => %{
      "cveId" => @cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2025-06-16T11:00:00.000Z",
      "dateUpdated" => "2025-06-17T12:00:00.000Z"
    },
    "containers" => %{
      "cna" => %{
        "title" => "Test vulnerability",
        "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
        "affected" => [],
        "references" => []
      }
    }
  }

  @other_published_cve_json %{
    "dataType" => "CVE_RECORD",
    "dataVersion" => "5.2",
    "cveMetadata" => %{
      "cveId" => @other_cve_id,
      "state" => "PUBLISHED",
      "datePublished" => "2025-06-10T08:00:00.000Z",
      "dateUpdated" => "2025-06-10T08:00:00.000Z"
    },
    "containers" => %{
      "cna" => %{
        "title" => "Another vulnerability",
        "descriptions" => [],
        "affected" => [],
        "references" => []
      }
    }
  }

  defp insert_published(cve_json) do
    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  defp insert_reserved(cve_id) do
    Ash.create!(
      CveRecord,
      %{
        reservation_json: %{
          "cve_id" => cve_id,
          "cve_year" => "2025",
          "state" => "RESERVED",
          "reserved" => "2025-01-01T00:00:00.000Z"
        }
      },
      action: :reserve,
      authorize?: false
    )
  end

  describe "GET /cves/index.json" do
    test "returns empty list when no published records", %{conn: conn} do
      conn = get(conn, "/cves/index.json")
      assert json_response(conn, 200) == []
    end

    test "returns published records sorted by datePublished descending", %{conn: conn} do
      insert_published(@other_published_cve_json)
      insert_published(@published_cve_json)

      conn = get(conn, "/cves/index.json")
      [first, second] = json_response(conn, 200)

      assert first["id"] == @cve_id
      assert first["title"] == "Test vulnerability"
      assert first["datePublished"] == "2025-06-16T11:00:00Z"
      assert first["dateUpdated"] == "2025-06-17T12:00:00Z"
      assert first["details"] == "/cves/#{@cve_id}.json"

      assert second["id"] == @other_cve_id
    end

    test "does not include unpublished records", %{conn: conn} do
      insert_reserved(@cve_id)

      conn = get(conn, "/cves/index.json")
      assert json_response(conn, 200) == []
    end
  end

  describe "GET /cves/:cve_id.json" do
    test "returns full CVE JSON for a published record", %{conn: conn} do
      insert_published(@published_cve_json)

      conn = get(conn, "/cves/#{@cve_id}.json")
      body = json_response(conn, 200)

      assert body["cveMetadata"]["cveId"] == @cve_id
      assert body["dataVersion"] == "5.2"
      assert body["containers"]["cna"]["title"] == "Test vulnerability"
    end

    test "returns 404 for unknown CVE ID", %{conn: conn} do
      conn = get(conn, "/cves/CVE-0000-00000.json")
      assert json_response(conn, 404) == %{}
    end

    test "returns 404 for unpublished record", %{conn: conn} do
      insert_reserved(@cve_id)

      conn = get(conn, "/cves/#{@cve_id}.json")
      assert json_response(conn, 404) == %{}
    end
  end
end
