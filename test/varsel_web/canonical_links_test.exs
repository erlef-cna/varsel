# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CanonicalLinksTest do
  @moduledoc """
  What a page tells search engines about its canonical URL and its other
  formats: the `<link>` elements in the head of an HTML page, and the `Link`
  header of the JSON forms of a CVE. The way in to the console is kept out
  of the index.
  """

  use VarselWeb.ConnCase, async: false

  alias Varsel.CVE.CveRecord
  alias Varsel.CVE.OsvRecord
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness

  @cve_id "CVE-2025-12345"

  defp publish! do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => @cve_id,
        "state" => "PUBLISHED",
        "datePublished" => "2026-04-27T12:00:00.000Z",
        "dateUpdated" => "2026-04-27T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "title" => "Test vulnerability",
          "descriptions" => [%{"lang" => "en", "value" => "A test vulnerability."}],
          "affected" => [%{"packageURL" => "pkg:hex/test_lib"}],
          "references" => [%{"url" => "https://example.com/advisory"}]
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  defp seed_osv_record!(cve_record) do
    now = DateTime.utc_now()

    Ash.Seed.seed!(OsvRecord, %{
      osv_id: "EEF-#{@cve_id}",
      cve_record_id: cve_record.id,
      osv_json: %{"id" => "EEF-#{@cve_id}", "aliases" => [@cve_id]},
      content_hash: "hash",
      modified_at: now,
      synced_at: now
    })
  end

  defp head_links(conn, rel) do
    conn
    |> html_response(200)
    |> LazyHTML.from_document()
    |> LazyHTML.query(~s(head link[rel="#{rel}"]))
    |> Enum.map(&{LazyHTML.attribute(&1, "href"), LazyHTML.attribute(&1, "type")})
  end

  defp canonical(conn) do
    [{[href], _type}] = head_links(conn, "canonical")
    href
  end

  defp absolute(path), do: VarselWeb.Endpoint.url() <> path

  describe "an HTML page" do
    test "names its own path on the configured host as canonical, without the query", %{
      conn: conn
    } do
      assert conn |> get(~p"/scope") |> canonical() == absolute("/scope")
      assert conn |> get("/cves?q=ash&page=2") |> canonical() == absolute("/cves")
    end

    test "an error page names no canonical URL", %{conn: conn} do
      html = conn |> get("/does-not-exist") |> html_response(404)

      assert html
             |> LazyHTML.from_document()
             |> LazyHTML.query(~s(link[rel="canonical"]))
             |> Enum.empty?()
    end
  end

  describe "the way in" do
    test "a link to the sign-in page asks crawlers not to follow it", %{conn: conn} do
      {401, _headers, refused} = assert_error_sent(401, fn -> get(conn, ~p"/cases") end)

      for html <- [conn |> get(~p"/scope") |> html_response(200), refused] do
        links = html |> LazyHTML.from_document() |> LazyHTML.query(~s(a[href^="/sign-in"]))

        refute Enum.empty?(links)
        assert Enum.all?(links, &(LazyHTML.attribute(&1, "rel") == ["nofollow"]))
      end
    end

    test "the sign-in page asks not to be indexed", %{conn: conn} do
      robots =
        conn
        |> get(~p"/sign-in")
        |> html_response(200)
        |> LazyHTML.from_document()
        |> LazyHTML.query(~s(head meta[name="robots"]))
        |> LazyHTML.attribute("content")

      assert robots == ["noindex, nofollow"]
    end
  end

  describe "a CVE" do
    setup do
      %{cve_record: publish!()}
    end

    test "its page is canonical and names its JSON forms as alternates", %{
      conn: conn,
      cve_record: cve_record
    } do
      seed_osv_record!(cve_record)
      conn = get(conn, ~p"/cves/#{@cve_id <> ".html"}")

      assert canonical(conn) == absolute("/cves/#{@cve_id}.html")

      assert head_links(conn, "alternate") == [
               {[absolute("/cves/#{@cve_id}.json")], ["application/json"]},
               {[absolute("/osv/EEF-#{@cve_id}.json")], ["application/json"]}
             ]
    end

    test "without an OSV record its page names the CVE record alone", %{conn: conn} do
      conn = get(conn, ~p"/cves/#{@cve_id <> ".html"}")

      assert head_links(conn, "alternate") == [
               {[absolute("/cves/#{@cve_id}.json")], ["application/json"]}
             ]
    end

    test "its CVE record and its OSV record name the page as canonical", %{
      conn: conn,
      cve_record: cve_record
    } do
      seed_osv_record!(cve_record)
      canonical = ~s(<#{absolute("/cves/#{@cve_id}.html")}>; rel="canonical")

      for path <- ["/cves/#{@cve_id}.json", "/osv/EEF-#{@cve_id}.json"] do
        conn = get(conn, path)

        assert json_response(conn, 200)
        assert get_resp_header(conn, "link") == [canonical]
      end
    end

    test "a JSON 404 names no canonical URL", %{conn: conn} do
      for path <- ["/cves/CVE-0000-00000.json", "/osv/EEF-CVE-0000-00000.json"] do
        conn = get(conn, path)

        assert json_response(conn, 404)
        assert get_resp_header(conn, "link") == []
      end
    end
  end

  describe "a weakness" do
    setup do
      for {view_id, name} <- [{1000, "Research Concepts"}, {1003, "Simplified Mapping"}] do
        Ash.Seed.seed!(View, %{
          view_id: view_id,
          name: name,
          type: :graph,
          status: :stable,
          objective: "#{name} objective"
        })
      end

      for {cwe_id, name} <- [
            {79, "Cross-site Scripting"},
            {613, "Insufficient Session Expiration"}
          ] do
        Ash.create!(
          Weakness,
          %{cwe_id: cwe_id, name: name, abstraction: :base, status: :stable, description: name},
          action: :upsert,
          authorize?: false
        )
      end

      for {view_id, cwe_id} <- [{1000, 79}, {1003, 79}, {1003, 613}] do
        Ash.Seed.seed!(ViewMembership, %{view_id: view_id, cwe_id: cwe_id})
      end

      Varsel.Repo.query!("REFRESH MATERIALIZED VIEW cwe_weakness_closure")
      :ok
    end

    test "its page in the default view is canonical from every view that reaches it", %{
      conn: conn
    } do
      assert conn |> get(~p"/common-weaknesses/1000/79") |> canonical() ==
               absolute("/common-weaknesses/1000/79")

      assert conn |> get(~p"/common-weaknesses/1003/79") |> canonical() ==
               absolute("/common-weaknesses/1000/79")
    end

    test "one the default view does not reach keeps its own page", %{conn: conn} do
      assert conn |> get(~p"/common-weaknesses/1003/613") |> canonical() ==
               absolute("/common-weaknesses/1003/613")
    end

    test "a view's own page stays canonical", %{conn: conn} do
      assert conn |> get(~p"/common-weaknesses/1003") |> canonical() ==
               absolute("/common-weaknesses/1003")
    end
  end
end
