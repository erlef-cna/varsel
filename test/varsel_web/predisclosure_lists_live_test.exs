# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.PredisclosureListsLiveTest do
  use VarselWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias Ash.Error.Forbidden
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Predisclosure

  require Ash.Query

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp shared_notifications(user) do
    Varsel.Notifications.Notification
    |> Ash.Query.filter(user_id == ^user.id and kind == :case_shared)
    |> Ash.read!(authorize?: false)
  end

  setup do
    %{
      poc: Fixtures.register_user("lists_live_poc", :poc),
      subscriber: Fixtures.register_user("lists_live_subscriber"),
      supporter: Fixtures.register_user("lists_live_supporter", :supporter)
    }
  end

  describe "the lists pages" do
    test "a POC creates a list and lands on it", %{conn: conn, poc: poc} do
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/predisclosure-lists")

      assert has_element?(lv, "nav a[href='/predisclosure-lists']")

      {:error, {:live_redirect, %{to: to}}} =
        lv
        |> form("#create-list-form", %{"form" => %{"name" => "Distributors"}})
        |> render_submit()

      [list] = Predisclosure.list_predisclosure_lists!(actor: poc)
      assert to == "/predisclosure-lists/#{list.id}"
    end

    test "a POC renames a list and manages its subscribers", %{
      conn: conn,
      poc: poc,
      subscriber: subscriber
    } do
      list = Predisclosure.create_predisclosure_list!("Distributors", actor: poc)
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/predisclosure-lists/#{list.id}")

      lv
      |> form("#rename-list-form", %{"form" => %{"name" => "Linux distributions"}})
      |> render_submit()

      assert Predisclosure.get_predisclosure_list!(list.id, actor: poc).name ==
               "Linux distributions"

      lv |> element("#add-subscriber") |> render_click()

      lv
      |> form("#subscriber-picker-form", %{"query" => "lists_live_subscriber"})
      |> render_change()

      lv
      |> form("#subscriber-picker-form", %{
        "query" => "lists_live_subscriber",
        "user_id" => subscriber.id
      })
      |> render_submit()

      assert has_element?(lv, "#list-subscribers li", "lists_live_subscriber")

      [row] = list |> Ash.load!(:subscribers, actor: poc) |> Map.fetch!(:subscribers)
      lv |> element("#subscriber-#{row.id} button", "Remove") |> render_click()

      refute has_element?(lv, "#subscriber-#{row.id}")
    end

    test "a POC deletes a list", %{conn: conn, poc: poc} do
      list = Predisclosure.create_predisclosure_list!("Short-lived", actor: poc)
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/predisclosure-lists/#{list.id}")

      assert {:error, {:live_redirect, %{to: "/predisclosure-lists"}}} =
               lv |> element("#delete-list") |> render_click()

      assert [] = Predisclosure.list_predisclosure_lists!(actor: poc)
    end

    test "nobody else gets the nav link or the pages", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      list = Predisclosure.create_predisclosure_list!("Distributors", actor: poc)
      conn = log_in(conn, supporter)

      {:ok, lv, _html} = live(conn, ~p"/cases")
      refute has_element?(lv, "nav a[href='/predisclosure-lists']")

      assert_raise Forbidden, fn -> live(conn, ~p"/predisclosure-lists") end
      assert_raise Forbidden, fn -> live(conn, ~p"/predisclosure-lists/#{list.id}") end
    end
  end

  describe "the case workspace" do
    test "a POC puts a case on several lists from the disclosure box, and takes it off again", %{
      conn: conn,
      poc: poc
    } do
      first = Predisclosure.create_predisclosure_list!("Distributors", actor: poc)
      second = Predisclosure.create_predisclosure_list!("Vendors", actor: poc)
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}")

      assert has_element?(lv, "#disclosure #case-lists", "none")

      lv |> element("#edit-lists") |> render_click()

      lv
      |> form("#case-lists-form", %{"list_ids" => ["", first.id, second.id]})
      |> render_submit()

      assert has_element?(lv, "#disclosure #case-list-#{first.id}", "Distributors")
      assert has_element?(lv, "#disclosure #case-list-#{second.id}", "Vendors")

      lv |> element("#edit-lists") |> render_click()
      lv |> form("#case-lists-form", %{"list_ids" => [""]}) |> render_submit()

      assert render(lv) =~ "none"
      refute has_element?(lv, "#case-list-#{first.id}")
    end

    test "a subscriber sees the case but not the lists it is on", %{
      conn: conn,
      poc: poc,
      subscriber: subscriber
    } do
      list = Predisclosure.create_predisclosure_list!("Distributors", actor: poc)
      Predisclosure.subscribe_to_predisclosure_list!(list.id, subscriber.id, actor: poc)
      case_record = Fixtures.open_case(poc, %{title: "Shared with distributors"})
      Cases.set_case_predisclosure_lists!(case_record, [list.id], actor: poc)

      Oban.drain_queue(queue: :default, with_recursion: true)
      assert [%{read_at: nil}] = shared_notifications(subscriber)

      {:ok, lv, _html} = conn |> log_in(subscriber) |> live(~p"/cases/#{case_record.id}")

      assert [%{read_at: %DateTime{}}] = shared_notifications(subscriber)
      refute has_element?(lv, "#case-lists")
      refute render(lv) =~ "Distributors"
      assert render(lv) =~ "Shared with distributors"
    end
  end
end
