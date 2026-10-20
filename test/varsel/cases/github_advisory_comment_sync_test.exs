# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryCommentSyncTest do
  @moduledoc """
  Reading the comments on a linked GitHub advisory: what the poll records,
  what it asks GitHub for, which links it visits, and who may run it.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Varsel.Cases
  alias Varsel.Cases.Comment
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.Fixtures
  alias Varsel.Notifications.Event
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  require Ash.Query

  @url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"

  setup do
    poc = Fixtures.register_user("comment_sync_poc", :poc)

    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: "ghs_acme_lib"
    )

    GitHubApp.seed_user_installations(poc, [7])

    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})

    %{poc: poc, case: case_record}
  end

  # The stub answers the advisory itself for a link, and `comments` for the
  # poll, recording each comments request so a test can assert what was asked.
  defp stub_comments(comments, opts \\ []) do
    test = self()
    status = Keyword.get(opts, :status, 200)

    GitHubApi.stub(fn conn ->
      case Enum.reverse(conn.path_info) do
        ["comments" | _rest] ->
          send(test, {:comments_request, conn.params, conn.req_headers})
          answer_comments(conn, comments, status)

        ["users", login] ->
          Req.Test.json(conn, %{"login" => login, "name" => nil, "email" => nil})

        _advisory ->
          Req.Test.json(conn, hex_advisory())
      end
    end)
  end

  defp answer_comments(conn, comments, 200), do: Req.Test.json(conn, comments)

  defp answer_comments(conn, _comments, status) do
    conn |> Plug.Conn.put_status(status) |> Req.Test.json(%{"message" => "nope"})
  end

  defp comment(id, body, login, overrides \\ %{}) do
    Map.merge(
      %{
        "id" => id,
        "body" => body,
        "html_url" => "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw#advisory-comment-#{id}",
        "created_at" => "2026-10-01T10:00:00Z",
        "updated_at" => "2026-10-01T10:00:00Z",
        "author_association" => "MEMBER",
        "user" => %{"login" => login, "id" => 42, "type" => "User"}
      },
      overrides
    )
  end

  defp link!(case_record, actor) do
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @url}, actor: actor)
  end

  defp comments(case_record, actor) do
    Cases.list_case_comments!(case_record.id, actor: actor)
  end

  defp unread_comment_notifications(user) do
    Varsel.Notifications.Notification
    |> Ash.Query.filter(is_nil(read_at) and kind == :comment_posted)
    |> Ash.read!(actor: user)
  end

  defp poll!(link) do
    Cases.sync_github_advisory_comments!(link, actor: Varsel.Service.github_comment_sync())
  end

  describe "the poll" do
    test "records each advisory comment as a case comment", %{case: case_record, poc: poc} do
      stub_comments([
        comment(1, "First from GitHub", "octocat"),
        comment(2, "And a second", "hubot")
      ])

      link = link!(case_record, poc)
      poll!(link)

      assert [first, second] = comments(case_record, poc)

      assert first.body == "First from GitHub"
      assert first.source == :github
      assert first.github_comment_id == 1
      assert first.github_author_login == "octocat"
      assert first.author_id == nil

      assert second.github_author_login == "hubot"
    end

    test "a comment written here keeps its own source and author", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "From GitHub", "octocat")])

      link = link!(case_record, poc)
      Cases.post_case_comment!(%{case_id: case_record.id, body: "From Varsel"}, actor: poc)
      poll!(link)

      by_source = case_record |> comments(poc) |> Map.new(&{&1.source, &1})

      assert by_source[:varsel].author_id == poc.id
      assert by_source[:varsel].github_comment_id == nil
      assert by_source[:github].author_id == nil
    end

    test "reading the same comment twice stores it once", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "Only once", "octocat")])

      link = link!(case_record, poc)
      poll!(link)

      link = Ash.reload!(link, actor: poc)
      poll!(link)

      assert [only] = comments(case_record, poc)
      assert only.github_comment_id == 1
    end

    test "an edited comment updates the body it already stored", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "First wording", "octocat")])

      link = link!(case_record, poc)
      poll!(link)

      stub_comments([comment(1, "Edited wording", "octocat")])
      poll!(Ash.reload!(link, actor: poc))

      assert [only] = comments(case_record, poc)
      assert only.body == "Edited wording"
    end

    test "stamps when it last read, and asks GitHub only for what changed since", %{
      case: case_record,
      poc: poc
    } do
      stub_comments([])

      link = link!(case_record, poc)
      assert link.comments_polled_at == nil

      polled = poll!(link)
      assert %DateTime{} = polled.comments_polled_at

      assert_received {:comments_request, first_params, _headers}
      refute Map.has_key?(first_params, "since")

      poll!(Ash.reload!(polled, actor: poc))

      assert_received {:comments_request, second_params, _headers}
      assert {:ok, since, _offset} = DateTime.from_iso8601(second_params["since"])
      assert DateTime.compare(since, polled.comments_polled_at) == :eq
    end

    test "reads with the App's installation token on the repository", %{
      case: case_record,
      poc: poc
    } do
      stub_comments([])

      poll!(link!(case_record, poc))

      assert_received {:comments_request, _params, headers}
      assert {"authorization", "Bearer ghs_acme_lib"} in headers
    end

    test "an empty answer records nothing and still stamps", %{case: case_record, poc: poc} do
      stub_comments([])

      polled = poll!(link!(case_record, poc))

      assert comments(case_record, poc) == []
      assert %DateTime{} = polled.comments_polled_at
    end

    test "a GitHub failure leaves the stamp unmoved, so the next poll asks again", %{
      case: case_record,
      poc: poc
    } do
      stub_comments([], status: 500)

      link = link!(case_record, poc)

      assert {:error, _error} =
               Cases.sync_github_advisory_comments(link,
                 actor: Varsel.Service.github_comment_sync()
               )

      assert Ash.reload!(link, actor: poc).comments_polled_at == nil
    end

    # GitHub answers `since` inclusively, so every poll re-reads the comment it
    # read last. That must not keep telling the case's people about it.
    test "re-reading an unchanged comment tells nobody a second time", %{
      case: case_record,
      poc: poc
    } do
      supporter = Fixtures.register_user("comment_sync_quiet", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      stub_comments([comment(1, "Same body every time", "octocat")])

      link = link!(case_record, poc)

      for _poll <- 1..3 do
        poll!(Ash.reload!(link, actor: poc))
      end

      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      assert [_one] = comments(case_record, poc)
      assert [%{count: 1}] = unread_comment_notifications(supporter)
    end

    test "an edited comment tells them again", %{case: case_record, poc: poc} do
      supporter = Fixtures.register_user("comment_sync_edited", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      stub_comments([comment(1, "First wording", "octocat")])
      link = link!(case_record, poc)
      poll!(link)

      stub_comments([comment(1, "Edited wording", "octocat")])
      poll!(Ash.reload!(link, actor: poc))

      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      assert [%{count: 2}] = unread_comment_notifications(supporter)
    end

    test "tells the case's people about a comment nobody here wrote", %{
      case: case_record,
      poc: poc
    } do
      supporter = Fixtures.register_user("comment_sync_supporter", :supporter)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      stub_comments([comment(1, "From GitHub", "octocat")])

      poll!(link!(case_record, poc))
      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      assert [_notification] = unread_comment_notifications(supporter)
    end
  end

  describe "naming the account behind a GitHub login" do
    test "names the account whose GitHub identity holds the login", %{
      case: case_record,
      poc: poc
    } do
      author = Fixtures.register_user("octocat", :supporter)

      stub_comments([comment(1, "Maintainer here", "octocat")])

      poll!(link!(case_record, poc))

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == author.id
      assert recorded.github_author_login == "octocat"
      assert recorded.source == :github
    end

    test "matches the login however GitHub capitalized it", %{case: case_record, poc: poc} do
      author = Fixtures.register_user("OctoCat", :supporter)

      stub_comments([comment(1, "Same person", "octocat")])

      poll!(link!(case_record, poc))

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == author.id
    end

    test "leaves the author unnamed when no account holds the login", %{
      case: case_record,
      poc: poc
    } do
      stub_comments([comment(1, "A stranger", "nobody-here")])

      poll!(link!(case_record, poc))

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == nil
      assert recorded.github_author_login == "nobody-here"
    end

    test "a hex handle matching the login names nobody", %{case: case_record, poc: poc} do
      Fixtures.sign_in_with_hex("octocat", System.unique_integer([:positive]))

      stub_comments([comment(1, "Not the same person", "octocat")])

      poll!(link!(case_record, poc))

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == nil
    end
  end

  describe "claiming comments when an identity is linked" do
    test "a later GitHub sign-in claims the comments it wrote", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "Wrote this before signing in", "latecomer")])

      poll!(link!(case_record, poc))

      assert [%{author_id: nil}] = comments(case_record, poc)

      author = Fixtures.register_user("latecomer", :supporter)

      assert [claimed] = comments(case_record, poc)
      assert claimed.author_id == author.id
      assert claimed.github_author_login == "latecomer"
    end

    test "claims every comment that login wrote, across cases", %{case: case_record, poc: poc} do
      other_case = Fixtures.open_case(poc, %{title: "Second case for the same person"})

      stub_comments([comment(1, "On the first", "prolific"), comment(2, "Also here", "prolific")])
      poll!(link!(case_record, poc))

      author = Fixtures.register_user("prolific", :supporter)

      claimed = comments(case_record, poc)
      assert length(claimed) == 2
      assert Enum.all?(claimed, &(&1.author_id == author.id))
      assert comments(other_case, poc) == []
    end

    test "leaves a comment another account already holds", %{case: case_record, poc: poc} do
      first = Fixtures.register_user("octocat", :supporter)

      stub_comments([comment(1, "Mine", "octocat")])
      poll!(link!(case_record, poc))

      Fixtures.register_user("someone-else", :supporter)

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == first.id
    end

    test "a hex sign-in claims nothing by its handle", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "Written on GitHub", "octocat")])
      poll!(link!(case_record, poc))

      Fixtures.sign_in_with_hex("octocat", System.unique_integer([:positive]))

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == nil
    end

    test "a comment written here is untouched by a sign-in", %{case: case_record, poc: poc} do
      stub_comments([])
      link!(case_record, poc)

      Cases.post_case_comment!(%{case_id: case_record.id, body: "From Varsel"}, actor: poc)

      Fixtures.register_user("octocat", :supporter)

      assert [recorded] = comments(case_record, poc)
      assert recorded.author_id == poc.id
      assert recorded.source == :varsel
    end
  end

  describe "which links the poll visits" do
    test "an open case with a repository advisory is due", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "Scheduled", "octocat")])

      link!(case_record, poc)
      AshOban.Test.schedule_and_run_triggers({GitHubAdvisoryLink, :sync_comments})

      assert [recorded] = comments(case_record, poc)
      assert recorded.github_comment_id == 1
    end

    test "a closed case is left alone", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "Too late", "octocat")])

      link!(case_record, poc)
      Cases.close_case!(case_record, %{closed_reason: "duplicate"}, actor: poc)

      AshOban.Test.schedule_and_run_triggers({GitHubAdvisoryLink, :sync_comments})

      assert comments(case_record, poc) == []
    end

    test "a link just polled is not polled again", %{case: case_record, poc: poc} do
      stub_comments([])

      poll!(link!(case_record, poc))
      assert_received {:comments_request, _params, _headers}

      AshOban.Test.schedule_and_run_triggers({GitHubAdvisoryLink, :sync_comments})

      refute_received {:comments_request, _params, _headers}
    end
  end

  describe "who may run it" do
    test "a POC may not: the poll is not a person's action", %{case: case_record, poc: poc} do
      stub_comments([])

      link = link!(case_record, poc)

      assert {:error, %Forbidden{}} = Cases.sync_github_advisory_comments(link, actor: poc)
    end

    test "a POC may not name a comment's author by hand", %{case: case_record, poc: poc} do
      stub_comments([comment(1, "From GitHub", "octocat")])
      poll!(link!(case_record, poc))

      assert [recorded] = comments(case_record, poc)

      assert {:error, %Forbidden{}} =
               Ash.update(recorded, %{author_id: poc.id},
                 action: :claim_for_identity,
                 actor: poc
               )
    end

    test "nobody may write a GitHub-sourced comment by hand", %{case: case_record, poc: poc} do
      input = %{case_id: case_record.id, body: "Forged", github_comment_id: 99}

      assert {:error, %Forbidden{}} =
               Ash.create(Comment, input, action: :sync_from_github, actor: poc)

      assert {:error, %Forbidden{}} =
               Ash.create(Comment, input, action: :sync_from_github, actor: nil)
    end
  end
end
