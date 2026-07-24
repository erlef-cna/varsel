# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.SitePagesTest do
  use VarselWeb.ConnCase, async: false

  test "GET / renders the homepage with the activity chart", %{conn: conn} do
    conn = get(conn, ~p"/")
    body = html_response(conn, 200)
    assert body =~ "Erlang Ecosystem Foundation"
    assert body =~ "CVE publications by quarter"
    assert body =~ "<svg"
  end

  for {path, needle} <- [
        {"/scope", "Scope"},
        {"/contact", "Report a Vulnerability"},
        {"/cve-criteria", "CVE Assignment Criteria"},
        {"/security-policy", "Security Policy"},
        {"/data-licensing", "Data Licensing"},
        {"/api-access", "API Access"},
        {"/coordinator-process", "Coordinator Process"},
        {"/maintainer-process", "Maintainer Process"}
      ] do
    test "GET #{path} renders", %{conn: conn} do
      conn = get(conn, unquote(path))
      assert html_response(conn, 200) =~ unquote(needle)
    end
  end

  test "API samples reference the deployment's own URL", %{conn: conn} do
    body = html_response(get(conn, "/api-access"), 200)

    assert body =~ "#{VarselWeb.Endpoint.url()}/mcp"
    refute body =~ "%BASE_URL%"
  end

  test "long pages render a table of contents with anchored headings", %{conn: conn} do
    conn = get(conn, ~p"/security-policy")
    body = html_response(conn, 200)

    # ToC nav + matching heading permalink anchor
    assert body =~ ~s(aria-label="Table of contents")
    assert body =~ ~s(id="introduction")
    assert body =~ ~s(class="anchor")
    assert body =~ ~s(href="#introduction")
  end

  test "GET /.well-known/security.txt is served", %{conn: conn} do
    conn = get(conn, "/.well-known/security.txt")
    assert response(conn, 200) =~ "Contact: mailto:cna@erlef.org"
  end

  describe "OSV id redirect" do
    test "GET /osv/EEF-CVE-....html 301-redirects to the canonical CVE .html page", %{conn: conn} do
      conn = get(conn, "/osv/EEF-CVE-2025-48042.html")
      assert redirected_to(conn, 301) == "/cves/CVE-2025-48042.html"
    end

    test "GET /osv/all.json still serves the feed index", %{conn: conn} do
      conn = get(conn, "/osv/all.json")
      assert json_response(conn, 200) == []
    end
  end

  describe "canonical URL contract" do
    test "GET /scope.html 301-redirects to the clean /scope", %{conn: conn} do
      conn = get(conn, "/scope.html")
      assert redirected_to(conn, 301) == "/scope"
    end
  end

  describe "GET /sitemap.xml" do
    setup do
      # A fresh persistent_term cache per test so a published record shows up.
      :persistent_term.erase({VarselWeb.SitemapController, :xml})
      :ok
    end

    test "lists home, the static pages, and every published CVE at its .html URL", %{conn: conn} do
      cve_id = "CVE-2025-48042"

      Ash.create!(
        Varsel.CVE.CveRecord,
        %{
          cve_json: %{
            "dataType" => "CVE_RECORD",
            "dataVersion" => "5.2",
            "cveMetadata" => %{
              "cveId" => cve_id,
              "state" => "PUBLISHED",
              "datePublished" => "2025-06-01T00:00:00Z"
            },
            "containers" => %{"cna" => %{}}
          }
        },
        action: :import,
        authorize?: false
      )

      conn = get(conn, "/sitemap.xml")
      body = response(conn, 200)

      assert response_content_type(conn, :xml) =~ "text/xml"
      assert body =~ "<urlset"

      base = VarselWeb.Endpoint.url()
      assert body =~ "<loc>#{base}/</loc>"
      assert body =~ "<loc>#{base}/scope</loc>"
      assert body =~ "<loc>#{base}/cves/#{cve_id}.html</loc>"
    end
  end
end
