# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.SitePagesTest do
  use CveManagementWeb.ConnCase, async: false

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
        {"/coordinator-process", "Coordinator Process"},
        {"/maintainer-process", "Maintainer Process"}
      ] do
    test "GET #{path} renders", %{conn: conn} do
      conn = get(conn, unquote(path))
      assert html_response(conn, 200) =~ unquote(needle)
    end
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
    test "GET /osv/EEF-CVE-... redirects to the CVE page", %{conn: conn} do
      conn = get(conn, "/osv/EEF-CVE-2025-48042")
      assert redirected_to(conn) == "/cves/CVE-2025-48042"
    end

    test "GET /osv/all.json still serves the feed index", %{conn: conn} do
      conn = get(conn, "/osv/all.json")
      assert json_response(conn, 200) == []
    end
  end
end
