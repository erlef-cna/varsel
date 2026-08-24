# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationSettingsLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Accounts
  alias Varsel.Fixtures
  alias Varsel.Notifications.Kind

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  test "an anonymous visitor is refused", %{conn: conn} do
    assert_raise VarselWeb.UnauthorizedError, fn -> live(conn, ~p"/settings/notifications") end
  end

  test "renders one row per kind", %{conn: conn} do
    user = Fixtures.register_user("notif_settings_rows")

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/notifications")

    for kind <- Kind.values() do
      assert has_element?(lv, "*", Kind.label(kind))
    end
  end

  test "saving turns off comment email and switches to the daily digest", %{conn: conn} do
    user = Fixtures.register_user("notif_settings_save")

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/settings/notifications")

    form_params =
      for kind <- Kind.values(), into: %{} do
        email = if kind == :comment_posted, do: "false", else: "true"

        {to_string(kind_index(kind)), %{"kind" => to_string(kind), "in_app" => "true", "email" => email}}
      end

    lv
    |> form("#notification-settings-form", %{
      "form" => %{
        "notification_email_mode" => "daily_digest",
        "notification_preferences" => form_params
      }
    })
    |> render_submit()

    assert has_element?(lv, "*", "Notification settings saved.")

    reloaded = Accounts.get_user_by_id!(user.id, actor: user)
    assert reloaded.notification_email_mode == :daily_digest

    comment_pref = Enum.find(reloaded.notification_preferences, &(&1.kind == :comment_posted))
    assert comment_pref.email == false
    assert comment_pref.in_app == true
  end

  defp kind_index(kind), do: Enum.find_index(Kind.values(), &(&1 == kind))
end
