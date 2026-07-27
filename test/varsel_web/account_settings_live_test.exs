# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.AccountSettingsLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Varsel.Fixtures

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts
  alias Varsel.Accounts.User

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  # A second provider on the same account, reporting a different address —
  # which is the only way a user has more than one to choose between.
  defp link_hex_identity(user, username, email) do
    Ash.create!(
      Varsel.Accounts.UserIdentity,
      %{
        user_id: user.id,
        strategy: "hex",
        user_info: %{"sub" => username, "preferred_username" => username, "email" => email},
        oauth_tokens: %{"access_token" => "token"}
      },
      action: :upsert,
      authorize?: false
    )
  end

  test "an anonymous visitor is refused", %{conn: conn} do
    assert_raise VarselWeb.UnauthorizedError, fn -> live(conn, ~p"/settings/account") end
  end

  test "lists every address a linked provider reported", %{conn: conn} do
    user = register_user("alice")
    link_hex_identity(user, "alice_hex", "alice@hex.example")

    {:ok, _lv, html} = conn |> log_in(user) |> live(~p"/settings/account")

    assert html =~ "alice@example.com"
    assert html =~ "alice@hex.example"
  end

  test "choosing an address sets it as the notification email", %{conn: conn} do
    user = register_user("alice")
    link_hex_identity(user, "alice_hex", "alice@hex.example")

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/account")

    html =
      lv
      |> element(~s{button[phx-value-notification_email="alice@hex.example"]})
      |> render_click()

    assert html =~ "Notification email set to alice@hex.example"

    assert to_string(Ash.get!(User, user.id, authorize?: false).notification_email) ==
             "alice@hex.example"
  end

  test "an address no linked provider reported is refused" do
    user = register_user("alice")

    assert {:error, _error} =
             Accounts.set_user_notification_email(
               user,
               %{notification_email: "attacker@example.com"},
               actor: user
             )

    assert to_string(Ash.get!(User, user.id, authorize?: false).notification_email) ==
             "alice@example.com"
  end

  test "nobody sets someone else's notification email" do
    alice = register_user("alice")
    poc = register_user("poc", :poc)
    link_hex_identity(alice, "alice_hex", "alice@hex.example")

    assert {:error, %Ash.Error.Forbidden{}} =
             Accounts.set_user_notification_email(
               alice,
               %{notification_email: "alice@hex.example"},
               actor: poc
             )
  end
end
