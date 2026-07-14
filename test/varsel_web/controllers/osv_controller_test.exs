# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.OsvControllerTest do
  use VarselWeb.ConnCase, async: false

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.OsvRecord

  @cve_id "CVE-2025-12345"
  @osv_id "EEF-CVE-2025-12345"

  setup do
    Application.put_env(:varsel, :hex_stub_packages, %{"test_lib" => ["1.0.0", "2.0.0"]})
    on_exit(fn -> Application.delete_env(:varsel, :hex_stub_packages) end)
  end

  defp insert_osv_record(cve_id \\ @cve_id) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "state" => "PUBLISHED",
        "datePublished" => "2026-04-27T12:00:00.000Z",
        "dateUpdated" => "2026-04-27T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "title" => "Test vulnerability",
          "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
          "affected" => [
            %{
              "vendor" => "Erlang Ecosystem Foundation",
              "product" => "test_lib",
              "packageURL" => "pkg:hex/test_lib",
              "defaultStatus" => "unaffected",
              "versions" => [
                %{
                  "version" => "0",
                  "lessThan" => "1.2.3",
                  "status" => "affected",
                  "versionType" => "semver"
                }
              ]
            }
          ],
          "references" => [%{"url" => "https://example.com/advisory"}]
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)

    OsvRecord
    |> Ash.ActionInput.for_action(:create_missing, %{})
    |> Ash.run_action!(authorize?: false)

    OsvRecord
    |> Ash.Query.for_read(:get, %{osv_id: "EEF-#{cve_id}"})
    |> Ash.read_one!(authorize?: false)
  end

  describe "GET /osv/all.json" do
    test "returns an empty list when there are no OSV records", %{conn: conn} do
      conn = get(conn, "/osv/all.json")
      assert json_response(conn, 200) == []
    end

    test "returns id and modified for every OSV record", %{conn: conn} do
      osv = insert_osv_record()

      conn = get(conn, "/osv/all.json")

      assert json_response(conn, 200) == [
               %{"id" => @osv_id, "modified" => DateTime.to_iso8601(osv.modified_at)}
             ]
    end
  end

  describe "GET /osv/:osv_id.json" do
    test "returns the full OSV document", %{conn: conn} do
      insert_osv_record()

      conn = get(conn, "/osv/#{@osv_id}.json")
      body = json_response(conn, 200)

      assert body["id"] == @osv_id
      assert body["schema_version"] == "1.7.3"
      assert body["aliases"] == [@cve_id]
      assert body["modified"]
      assert [%{"package" => %{"ecosystem" => "Hex", "name" => "test_lib"}}] = body["affected"]
    end

    test "returns 404 for unknown OSV IDs", %{conn: conn} do
      conn = get(conn, "/osv/EEF-CVE-0000-00000.json")
      assert json_response(conn, 404) == %{}
    end
  end
end
