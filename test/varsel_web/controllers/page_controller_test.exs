# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.PageControllerTest do
  use VarselWeb.ConnCase, async: false

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert html_response(conn, 200) =~ "Erlang Ecosystem Foundation CNA"
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

    test "GET /robots.txt allows everything", %{conn: conn} do
      conn = get(conn, "/robots.txt")

      body = response(conn, 200)
      assert body =~ "User-agent: *"
      refute body =~ "Disallow: /"
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
