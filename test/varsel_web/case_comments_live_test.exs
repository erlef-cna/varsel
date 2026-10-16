# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseCommentsLiveTest do
  use VarselWeb.ConnCase, async: true

  import Phoenix.LiveViewTest

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Notifications.Event

  require Ash.Query

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("case_comments_poc", :poc)
    supporter = Fixtures.register_user("case_comments_supporter", :supporter)

    %{conn: conn, poc: poc, supporter: supporter}
  end

  describe "comments tab" do
    test "sends an anonymous caller away without saying the case exists", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc)

      assert {:error, {:live_redirect, %{to: "/cases", flash: flash}}} =
               live(conn, ~p"/cases/#{case_record.id}/comments")

      assert flash == %{"error" => "Case not found."}
    end

    test "shows the whole stream, oldest first", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      for body <- ["first thought", "second thought"] do
        Cases.post_case_comment!(%{case_id: case_record.id, body: body}, actor: poc)
      end

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      [first, second] = Cases.list_case_comments!(case_record.id, actor: poc)

      assert has_element?(lv, "#comment-#{first.id}", "first thought")
      assert has_element?(lv, "#comment-#{second.id}", "second thought")

      html = render(lv)
      assert :binary.match(html, "first thought") < :binary.match(html, "second thought")
    end

    test "renders one card per comment, past the workspace rail's 25-entry cut", %{
      conn: conn,
      poc: poc
    } do
      case_record = Fixtures.open_case(poc)

      for n <- 1..30 do
        Cases.post_case_comment!(
          %{case_id: case_record.id, body: "comment number #{n}"},
          actor: poc
        )
      end

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      comments = Cases.list_case_comments!(case_record.id, actor: poc)
      assert length(comments) == 30

      cards = lv |> render() |> then(&Regex.scan(~r/<article id="comment-/, &1)) |> length()
      assert cards == 30

      for comment <- comments do
        assert has_element?(lv, "#comment-#{comment.id}")
      end
    end

    test "posts a comment", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      lv
      |> form("#case-comment-form", %{"form" => %{"body" => "Looks good to me"}})
      |> render_submit()

      assert render(lv) =~ "Looks good to me"

      assert [%{body: "Looks good to me"}] =
               Cases.list_case_comments!(case_record.id, actor: poc)
    end

    test "clears the form after posting", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      lv
      |> form("#case-comment-form", %{"form" => %{"body" => "posted once"}})
      |> render_submit()

      body = lv |> element("#case-comment-form textarea") |> render()

      refute body =~ "posted once"
    end

    test "an empty body is refused inline, not raised", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      html =
        lv
        |> form("#case-comment-form", %{"form" => %{"body" => ""}})
        |> render_submit()

      assert html =~ "is required"
      assert Cases.list_case_comments!(case_record.id, actor: poc) == []
      assert render(lv) =~ "Add a comment"
    end

    test "an assigned supporter may read and post", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/comments")

      lv
      |> form("#case-comment-form", %{"form" => %{"body" => "from the supporter"}})
      |> render_submit()

      assert render(lv) =~ "from the supporter"
    end

    test "an unassigned supporter cannot reach the tab", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)

      assert {:error, {:live_redirect, %{to: "/cases"}}} =
               conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/comments")
    end

    test "a closed case still takes comments", %{conn: conn, poc: poc} do
      case_record = Fixtures.open_case(poc)
      Cases.close_case!(case_record, %{closed_reason: "duplicate"}, actor: poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")

      lv
      |> form("#case-comment-form", %{"form" => %{"body" => "post-mortem note"}})
      |> render_submit()

      assert render(lv) =~ "post-mortem note"
    end
  end

  describe "notifications" do
    setup %{poc: poc, supporter: supporter} do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      Cases.post_case_comment!(
        %{case_id: case_record.id, body: "while you were away"},
        actor: supporter
      )

      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      %{case_record: case_record}
    end

    test "the comments tab marks the comment read", %{
      conn: conn,
      poc: poc,
      case_record: case_record
    } do
      assert unread_kinds(poc) == [:comment_posted]

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/comments")
      assert render(lv) =~ "while you were away"

      assert unread_kinds(poc) == []
    end

    # A tab that does not show the comment must leave its notification alone,
    # or the bell clears itself the moment the comment arrives.
    for {tab, path} <- [workspace: "", cve: "/cve", github: "/github"] do
      test "the #{tab} tab leaves the comment unread", %{
        conn: conn,
        poc: poc,
        case_record: case_record
      } do
        {:ok, lv, _html} =
          conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}" <> unquote(path))

        _flushed = render(lv)

        assert unread_kinds(poc) == [:comment_posted]
      end
    end
  end

  describe "unseen marker" do
    setup %{poc: poc, supporter: supporter} do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      for body <- ["one", "two", "three"] do
        Cases.post_case_comment!(%{case_id: case_record.id, body: body}, actor: poc)
      end

      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      %{case_record: case_record}
    end

    # The marker counts what the reader has not been told about, so the
    # person who wrote everything has nothing waiting.
    test "the author of every comment sees no marker", %{
      conn: conn,
      poc: poc,
      case_record: case_record
    } do
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/cve")

      refute unseen_label(render(lv))
    end

    for {tab, path} <- [workspace: "", cve: "/cve", github: "/github"] do
      test "the #{tab} tab marks how many wait", %{
        conn: conn,
        supporter: supporter,
        case_record: case_record
      } do
        {:ok, lv, _html} =
          conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}" <> unquote(path))

        assert unseen_label(render(lv)) == "3 new comments"
      end
    end

    test "opening the comments tab clears it in the same render", %{
      conn: conn,
      supporter: supporter,
      case_record: case_record
    } do
      {:ok, lv, _html} =
        conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/comments")

      refute unseen_label(render(lv))
    end

    test "a comment arriving on another tab raises the count", %{
      conn: conn,
      poc: poc,
      supporter: supporter,
      case_record: case_record
    } do
      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/cve")
      assert unseen_label(render(lv)) == "3 new comments"

      Cases.post_case_comment!(%{case_id: case_record.id, body: "four"}, actor: poc)
      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      assert unseen_label(render(lv)) == "4 new comments"
    end

    test "one waiting comment reads as one", %{
      conn: conn,
      poc: poc,
      supporter: supporter
    } do
      case_record = Fixtures.open_case(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      Cases.post_case_comment!(%{case_id: case_record.id, body: "only"}, actor: poc)
      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/cve")

      assert unseen_label(render(lv)) == "1 new comment"
    end

    test "the total count stays whatever the stream holds", %{
      conn: conn,
      supporter: supporter,
      case_record: case_record
    } do
      {:ok, lv, _html} =
        conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/comments")

      html = render(lv)

      assert tab_count(html, case_record.id) == "3"
      refute unseen_label(html)
    end
  end

  describe "comments tab link" do
    test "counts the stream and drops a zero", %{conn: conn, poc: poc} do
      quiet = Fixtures.open_case(poc, %{title: "Quiet case"})
      busy = Fixtures.open_case(poc, %{title: "Busy case"})

      Cases.post_case_comment!(%{case_id: busy.id, body: "one"}, actor: poc)

      {:ok, _lv, quiet_html} = conn |> log_in(poc) |> live(~p"/cases/#{quiet.id}")
      {:ok, _lv, busy_html} = conn |> log_in(poc) |> live(~p"/cases/#{busy.id}")

      assert tab_count(quiet_html, quiet.id) == nil
      assert tab_count(busy_html, busy.id) == "1"
    end
  end

  # The marker names what waits, so what it says is what is asserted.
  defp unseen_label(html) do
    case Regex.run(~r/aria-label="(\d+ new comments?)"/, html, capture: :all_but_first) do
      [label] -> label
      nil -> nil
    end
  end

  defp unread_kinds(user) do
    Varsel.Notifications.Notification
    |> Ash.Query.filter(is_nil(read_at))
    |> Ash.read!(actor: user)
    |> Enum.map(& &1.kind)
    |> Enum.sort()
  end

  # The count is the inner span of the Comments tab's own link, found by the
  # href that carries the case id, so another tab's count cannot be read as
  # this one's. A tab with no count renders no inner span at all.
  defp tab_count(html, case_id) do
    link =
      case Regex.run(~r|<a href="/cases/#{case_id}/comments".*?>(.*?)</a>|s, html, capture: :all_but_first) do
        [link] -> link
        nil -> flunk("no Comments tab link for case #{case_id}")
      end

    case Regex.run(~r|<span[^>]*tabular-nums[^>]*>(.*?)</span>|s, link, capture: :all_but_first) do
      [count] -> String.trim(count)
      nil -> nil
    end
  end
end
