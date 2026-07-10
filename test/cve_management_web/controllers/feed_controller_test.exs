# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.FeedControllerTest do
  use CveManagementWeb.ConnCase, async: false

  alias CveManagement.CVE.CveRecord

  @cve_id "CVE-2025-12345"

  defp publish do
    cve_json = %{
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

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  describe "GET /feed.atom" do
    test "returns a valid atom feed with the right content type", %{conn: conn} do
      publish()

      conn = get(conn, ~p"/feed.atom")

      assert conn |> get_resp_header("content-type") |> hd() =~ "application/atom+xml"
      body = response(conn, 200)
      assert body =~ "<feed xmlns=\"http://www.w3.org/2005/Atom\">"
      assert body =~ @cve_id
      assert body =~ "Test vulnerability"
      assert body =~ "/cves/#{@cve_id}"
    end
  end

  describe "GET /feed.rss" do
    test "returns a valid rss feed with the right content type", %{conn: conn} do
      publish()

      conn = get(conn, ~p"/feed.rss")

      assert conn |> get_resp_header("content-type") |> hd() =~ "application/rss+xml"
      body = response(conn, 200)
      assert body =~ "<rss version=\"2.0\""
      assert body =~ @cve_id
    end
  end
end
