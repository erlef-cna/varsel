# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.ApiKeySettingsLiveTest do
  use CveManagementWeb.ConnCase, async: false

  import CveManagement.Fixtures
  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias CveManagement.Accounts

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  test "an anonymous visitor is redirected to sign in", %{conn: conn} do
    assert {:error, {:redirect, %{to: "/sign-in"}}} = live(conn, ~p"/settings/tokens")
  end

  test "creating a token shows the plaintext exactly once", %{conn: conn} do
    user = register_user("alice")

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/tokens")

    html =
      lv
      |> form("form[phx-submit=create]", %{
        "form" => %{"name" => "CI pipeline"},
        "expiry" => "never"
      })
      |> render_submit()

    assert html =~ "CI pipeline"
    assert html =~ "eefcna_"

    # A fresh mount must not reveal the plaintext again.
    {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/tokens")
    assert html =~ "CI pipeline"
    refute html =~ "eefcna_"
  end

  test "revoking a token removes it", %{conn: conn} do
    user = register_user("alice")
    {api_key, _plaintext} = create_api_key(user, %{name: "old key"})

    {:ok, lv, html} = conn |> log_in(user) |> live(~p"/settings/tokens")
    assert html =~ "old key"

    lv
    |> element(~s(button[phx-click=revoke][phx-value-id="#{api_key.id}"]))
    |> render_click()

    refute has_element?(lv, ~s(button[phx-value-id="#{api_key.id}"]))
    assert Accounts.list_api_keys!(actor: user) == []
  end

  test "users only see their own tokens", %{conn: conn} do
    alice = register_user("alice")
    bob = register_user("bob")
    create_api_key(bob, %{name: "bobs key"})

    {:ok, _lv, html} = conn |> log_in(alice) |> live(~p"/settings/tokens")

    refute html =~ "bobs key"
    assert html =~ "No tokens yet"
  end
end
