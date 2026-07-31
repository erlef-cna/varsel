# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ReturnPathFlowTest do
  use VarselWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  describe "a page that requires signing in" do
    test "sends an anonymous caller to sign in, naming where to come back to", %{conn: conn} do
      conn = get(conn, ~p"/settings/account/link/start/github")

      assert redirected_to(conn) ==
               ~p"/sign-in?return_to=%2Fsettings%2Faccount%2Flink%2Fstart%2Fgithub"
    end

    test "keeps the query string of the page it turned away", %{conn: conn} do
      conn = get(conn, ~p"/settings/account/link/start/github?foo=bar")

      assert redirected_to(conn) =~
               "return_to=" <> URI.encode_www_form("/settings/account/link/start/github?foo=bar")
    end
  end

  describe "the /report LiveView" do
    test "sends an anonymous visitor to sign in, returning to /report", %{conn: conn} do
      assert {:error, {:redirect, %{to: to}}} = live(conn, ~p"/report")
      assert to == ~p"/sign-in?return_to=%2Freport"
    end
  end

  describe "the sign-in page" do
    test "parks a valid return path in the session", %{conn: conn} do
      conn = get(conn, ~p"/sign-in?return_to=%2Freport")

      assert get_session(conn, :return_to) == "/report"
    end

    test "ignores a return path that would leave the site", %{conn: conn} do
      conn = get(conn, ~p"/sign-in?return_to=https%3A%2F%2Fevil.com")

      refute get_session(conn, :return_to)
    end

    test "ignores a protocol-relative return path", %{conn: conn} do
      conn = get(conn, ~p"/sign-in?return_to=%2F%2Fevil.com")

      refute get_session(conn, :return_to)
    end

    test "stores nothing when no return path is given", %{conn: conn} do
      conn = get(conn, ~p"/sign-in")

      refute get_session(conn, :return_to)
    end
  end

  describe "signing out" do
    # /sign-out is on the same pipeline and spends the same session key, so a
    # crafted link must not be able to choose where signing out lands.
    test "ignores a return path in its own query string", %{conn: conn} do
      conn = delete(conn, "/sign-out?return_to=%2Fcves")

      assert redirected_to(conn) == ~p"/"
    end
  end

  describe "the nav's sign-in button" do
    test "carries the page the visitor is on", %{conn: conn} do
      body = conn |> get(~p"/cves") |> html_response(200)

      assert body =~ "/sign-in?return_to=" <> URI.encode_www_form("/cves")
    end

    # Returning to the way in would bounce the caller straight back out.
    test "does not offer to return to the sign-in page itself", %{conn: conn} do
      body = conn |> get(~p"/sign-in") |> html_response(200)

      refute body =~ "return_to"
    end
  end

  describe "the 401 page" do
    # `assert_error_sent` runs the raised error through the endpoint's real
    # error rendering, which is the only way to see the page a visitor gets.
    test "its sign-in button returns to the page that refused", %{conn: conn} do
      {401, _headers, body} =
        assert_error_sent(401, fn -> get(conn, ~p"/settings/account") end)

      assert body =~ "/sign-in?return_to=" <> URI.encode_www_form("/settings/account")
    end
  end
end
