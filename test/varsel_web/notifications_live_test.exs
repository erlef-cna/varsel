# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.NotificationsLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Notifications

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp record!(user, case_record, kind \\ :comment_posted) do
    Notifications.record_notification!(
      %{kind: kind, user_id: user.id, case_id: case_record.id},
      authorize?: false
    )
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("notif_live_poc", :poc)
    other = Fixtures.register_user("notif_live_other", :supporter)
    case_record = Fixtures.open_case(poc, %{title: "Notified about this"})

    %{conn: conn, poc: poc, other: other, case: case_record}
  end

  test "an anonymous visitor is refused", %{conn: conn} do
    assert_raise Ash.Error.Forbidden, fn -> live(conn, ~p"/notifications") end
  end

  test "the empty state shows with no notifications", %{conn: conn, poc: poc} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")

    assert has_element?(lv, "*", "Nothing to see yet.")
    assert has_element?(lv, "*", "Nothing unread")
  end

  test "a case-kind row headlines the case title, an absorbed count and a subject link", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    record!(poc, case_record)
    record!(poc, case_record)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")

    assert has_element?(lv, "a[href='/cases/#{case_record.id}']", "Notified about this")
    assert has_element?(lv, "*", "New comment")
    assert has_element?(lv, "*", "2×")
    assert has_element?(lv, "a[href='/cases/#{case_record.id}']", "Open case →")
  end

  test "a case with an assigned CVE ID shows it as a chip beside the title", %{
    conn: conn,
    poc: poc
  } do
    year = Date.utc_today().year
    record = Fixtures.reserved_cve_record("CVE-#{year}-31900")
    case_record = Fixtures.open_case(poc, %{title: "Has a CVE ID"})
    Cases.assign_case_cve_id!(case_record, %{cve_record_id: record.id}, actor: poc)
    record!(poc, case_record)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")

    assert has_element?(lv, "a[href='/cases/#{case_record.id}']", "Has a CVE ID")
    assert has_element?(lv, "*", "CVE-#{year}-31900")
  end

  test "a row for a case the viewer is no longer assigned to falls back to the kind label", %{
    conn: conn,
    poc: poc,
    other: other,
    case: case_record
  } do
    assignment =
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: other.id}, actor: poc)

    record!(other, case_record)
    Cases.unassign_case_user!(assignment, actor: poc)

    {:ok, lv, _html} = conn |> log_in(other) |> live(~p"/notifications")

    refute has_element?(lv, "a", case_record.title)
    assert has_element?(lv, "a[href='/cases/#{case_record.id}']", "New comment")
  end

  test "toggling a row read updates its button and the unread count in the header", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    notification = record!(poc, case_record)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")
    assert has_element?(lv, "*", "1 unread")
    assert has_element?(lv, "button[phx-value-row_id='#{notification.id}']", "Mark read")

    lv
    |> element("button[phx-click=toggle_read][phx-value-row_id='#{notification.id}']")
    |> render_click()

    render(lv)
    assert has_element?(lv, "*", "Nothing unread")
    assert has_element?(lv, "button[phx-value-row_id='#{notification.id}']", "Mark unread")
  end

  test "toggling an unknown row flashes an error instead of crashing", %{conn: conn, poc: poc} do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")

    render_click(lv, "toggle_read", %{"row_id" => Ecto.UUID.generate()})

    assert has_element?(lv, "*", "Could not update that notification.")
  end

  test "another user's notifications are not shown", %{
    conn: conn,
    poc: poc,
    other: other,
    case: case_record
  } do
    record!(other, case_record)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")

    assert has_element?(lv, "*", "Nothing to see yet.")
  end

  test "the nested bell reflects the unread count and updates after a new notification", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/notifications")
    bell = find_live_child(lv, "notification-bell")

    refute render(bell) =~ "badge-info"

    record!(poc, case_record)

    assert render(bell) =~ ~r/badge-info[^>]*>\s*1\s*</
  end
end
