# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.PageControllerTest do
  use VarselWeb.ConnCase, async: false

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Fixtures

  # RFC 9309 §2.2.3: `*` matches any characters, a trailing `$` anchors the end.
  defp disallow_rules(body) do
    for "Disallow: " <> pattern <- String.split(body, "\n") do
      regex =
        pattern
        |> Regex.escape()
        |> String.replace("\\*", ".*")
        |> String.replace(~r/\\\$$/, "$")

      Regex.compile!("^" <> regex)
    end
  end

  defp blocked?(rules, path), do: Enum.any?(rules, &Regex.match?(&1, path))

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert html_response(conn, 200) =~ "Erlang Ecosystem Foundation CNA"
  end

  test "an anonymous visitor's dead render carries no notification bell", %{conn: conn} do
    conn = get(conn, ~p"/")
    refute html_response(conn, 200) =~ ~s(aria-label="Notifications")
  end

  test "a signed-in visitor's dead render mounts the nested notification bell", %{conn: conn} do
    user = Fixtures.register_user("page_bell_dead_render")
    conn = conn |> log_in(user) |> get(~p"/")

    assert html_response(conn, 200) =~ ~s(aria-label="Notifications")
  end

  test "the retired report triage page redirects to the case board", %{conn: conn} do
    conn = get(conn, "/reports")

    assert redirected_to(conn, 301) == ~p"/cases"
  end

  describe "test deployment (search indexing blocked)" do
    setup do
      previous = Application.fetch_env!(:varsel, :test_deployment?)
      Application.put_env(:varsel, :test_deployment?, true)
      on_exit(fn -> Application.put_env(:varsel, :test_deployment?, previous) end)
    end

    test "GET /robots.txt disallows everything", %{conn: conn} do
      conn = get(conn, "/robots.txt")

      assert response_content_type(conn, :txt) =~ "text/plain"
      body = response(conn, 200)
      assert body =~ "User-agent: *"
      assert body =~ "Disallow: /"
    end

    test "responses carry the X-Robots-Tag header", %{conn: conn} do
      conn = get(conn, ~p"/")

      assert get_resp_header(conn, "x-robots-tag") == ["noindex, nofollow, noarchive"]
    end

    test "home page shows the test deployment warning", %{conn: conn} do
      conn = get(conn, ~p"/")
      assert html_response(conn, 200) =~ "test deployment"
    end
  end

  describe "production deployment (search indexing allowed)" do
    setup do
      previous = Application.fetch_env!(:varsel, :test_deployment?)
      Application.put_env(:varsel, :test_deployment?, false)
      on_exit(fn -> Application.put_env(:varsel, :test_deployment?, previous) end)
    end

    test "GET /robots.txt links the sitemap", %{conn: conn} do
      conn = get(conn, "/robots.txt")

      body = response(conn, 200)
      assert body =~ "User-agent: *"
      assert body =~ "Sitemap: #{VarselWeb.Endpoint.url()}/sitemap.xml"
    end

    test "GET /robots.txt allows the public pages", %{conn: conn} do
      rules = conn |> get("/robots.txt") |> response(200) |> disallow_rules()

      for path <- [
            "/",
            "/cves",
            "/guide/filing-a-case",
            "/common-weaknesses/1000",
            "/cves/CVE-2026-0001.html",
            "/cves/CVE-2026-0001",
            "/osv/EEF-CVE-2026-0001",
            "/feed.atom",
            "/sitemap.xml",
            "/.well-known/security.txt"
          ] do
        refute blocked?(rules, path), "#{path} is disallowed"
      end
    end

    test "GET /robots.txt disallows auth, API and sign-in-only paths", %{conn: conn} do
      rules = conn |> get("/robots.txt") |> response(200) |> disallow_rules()

      for path <- [
            "/auth/user/github",
            "/sign-in",
            "/sign-out",
            "/register",
            "/reset",
            "/magic_link/token",
            "/oauth/authorize",
            "/.well-known/oauth-authorization-server",
            "/cases",
            "/cases/0d1f/cve",
            "/reports",
            "/report",
            "/users",
            "/notifications",
            "/settings/account",
            "/cves/manage/0d1f",
            "/api/hex/reports",
            "/gql",
            "/mcp",
            "/live/websocket",
            "/cves/index.json",
            "/cves/CVE-2026-0001.json",
            "/osv/all.json",
            "/osv/EEF-CVE-2026-0001.json"
          ] do
        assert blocked?(rules, path), "#{path} is allowed"
      end
    end

    test "responses do not carry the X-Robots-Tag header", %{conn: conn} do
      conn = get(conn, ~p"/")

      assert get_resp_header(conn, "x-robots-tag") == []
    end

    test "home page hides the test deployment warning", %{conn: conn} do
      conn = get(conn, ~p"/")
      refute html_response(conn, 200) =~ "This is a"
    end
  end
end
