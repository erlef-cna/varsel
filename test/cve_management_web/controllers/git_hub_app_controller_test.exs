# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.GitHubAppControllerTest do
  use CveManagementWeb.ConnCase, async: false

  alias CveManagement.Accounts.GitHubAppToken
  alias CveManagement.GitHub.AppClient

  defp create_user do
    CveManagement.Accounts.User
    |> Ash.Changeset.for_create(
      :register_with_github,
      %{
        user_info: %{
          "sub" => System.unique_integer([:positive]),
          "preferred_username" => "testuser",
          "name" => "Test User",
          "email" => "test@example.com"
        },
        oauth_tokens: %{"access_token" => "gho_test"}
      },
      authorize?: false
    )
    |> Ash.create!(authorize?: false)
  end

  defp log_in(conn, user) do
    {:ok, token, _claims} = AshAuthentication.Jwt.token_for_user(user)

    conn
    |> init_test_session(%{})
    |> put_session("user_token", token)
    |> assign(:current_user, user)
  end

  defp stub_exchange_success do
    Req.Test.stub(AppClient, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(
        200,
        Jason.encode!(%{
          "access_token" => "ghu_new_access",
          "refresh_token" => "ghr_new_refresh",
          "expires_in" => 28_800,
          "token_type" => "bearer"
        })
      )
    end)
  end

  defp stub_exchange_error do
    Req.Test.stub(AppClient, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(200, Jason.encode!(%{"error" => "bad_verification_code"}))
    end)
  end

  describe "GET /auth/github_app" do
    test "redirects unauthenticated user to sign in", %{conn: conn} do
      conn = get(conn, "/auth/github_app")
      assert redirected_to(conn) =~ "/sign-in"
    end

    test "redirects authenticated user to GitHub authorization URL", %{conn: conn} do
      user = create_user()
      conn = conn |> log_in(user) |> get("/auth/github_app")

      location = redirected_to(conn, 302)
      assert location =~ "github.com/login/oauth/authorize"
      assert location =~ "client_id="
      assert location =~ "state="
    end

    test "stores oauth state in session", %{conn: conn} do
      user = create_user()
      conn = conn |> log_in(user) |> get("/auth/github_app")

      assert get_session(conn, :github_app_oauth_state)
    end
  end

  describe "GET /auth/github_app/callback" do
    test "redirects unauthenticated user to sign in", %{conn: conn} do
      conn = get(conn, "/auth/github_app/callback", %{"code" => "abc", "state" => "xyz"})
      assert redirected_to(conn) =~ "/sign-in"
    end

    test "stores token and redirects to settings on success", %{conn: conn} do
      stub_exchange_success()
      user = create_user()

      conn =
        conn
        |> log_in(user)
        |> init_test_session(%{github_app_oauth_state: "valid_state"})
        |> get("/auth/github_app/callback", %{"code" => "valid_code", "state" => "valid_state"})

      assert redirected_to(conn) == "/settings"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ "connected"

      assert [token] = Ash.read!(GitHubAppToken, authorize?: false)
      assert token.user_id == user.id
      assert token.status == :valid
    end

    test "redirects to settings with error on invalid state", %{conn: conn} do
      user = create_user()

      conn =
        conn
        |> log_in(user)
        |> init_test_session(%{github_app_oauth_state: "correct_state"})
        |> get("/auth/github_app/callback", %{"code" => "abc", "state" => "wrong_state"})

      assert redirected_to(conn) == "/settings"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "Invalid OAuth state"
    end

    test "redirects to settings with error when GitHub returns an error", %{conn: conn} do
      stub_exchange_error()
      user = create_user()

      conn =
        conn
        |> log_in(user)
        |> init_test_session(%{github_app_oauth_state: "valid_state"})
        |> get("/auth/github_app/callback", %{"code" => "bad_code", "state" => "valid_state"})

      assert redirected_to(conn) == "/settings"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "failed"
      assert Ash.count!(GitHubAppToken, authorize?: false) == 0
    end

    test "redirects to settings with error when code is missing", %{conn: conn} do
      user = create_user()

      conn =
        conn
        |> log_in(user)
        |> get("/auth/github_app/callback", %{})

      assert redirected_to(conn) == "/settings"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "denied"
    end
  end
end
