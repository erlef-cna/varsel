# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisoryCrossPostTest do
  @moduledoc """
  Writing a comment to the case's linked GitHub advisory: whose credential
  carries it, what the body says, and what a refusal does to the case.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Notifications.Event
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  require Ash.Query

  @url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"

  setup do
    poc = Fixtures.register_user("cross_post_poc", :poc)

    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: "ghs_acme_lib"
    )

    %{poc: poc}
  end

  # Records every comment write so a test can assert the body and the
  # credential GitHub was handed.
  defp stub_writes(opts \\ []) do
    test = self()
    status = Keyword.get(opts, :status, 201)

    GitHubApi.stub(fn conn ->
      case {conn.method, Enum.reverse(conn.path_info)} do
        {"POST", ["comments" | _rest]} ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          send(test, {:comment_write, Jason.decode!(body), conn.req_headers})
          answer_write(conn, status)

        {_method, ["comments" | _rest]} ->
          Req.Test.json(conn, [])

        {_method, ["users", login]} ->
          Req.Test.json(conn, %{"login" => login, "name" => nil, "email" => nil})

        _advisory ->
          Req.Test.json(conn, hex_advisory())
      end
    end)
  end

  defp answer_write(conn, 201) do
    conn
    |> Plug.Conn.put_status(201)
    |> Req.Test.json(%{
      "id" => 9001,
      "html_url" => "#{@url}#advisory-comment-9001",
      "body" => "recorded"
    })
  end

  defp answer_write(conn, status) do
    conn |> Plug.Conn.put_status(status) |> Req.Test.json(%{"message" => "nope"})
  end

  defp link!(case_record, actor) do
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @url}, actor: actor)
  end

  defp open_linked_case(poc) do
    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})
    link!(case_record, poc)
    case_record
  end

  defp open_linked_case_with_link(poc) do
    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})
    {case_record, link!(case_record, poc)}
  end

  defp unread_comment_notifications(user) do
    Varsel.Notifications.Notification
    |> Ash.Query.filter(is_nil(read_at) and kind == :comment_posted)
    |> Ash.read!(actor: user)
  end

  defp post!(case_record, actor, body, cross_post) do
    Cases.post_case_comment!(
      %{case_id: case_record.id, body: body, cross_post: cross_post},
      actor: actor
    )
  end

  describe "whose credential carries the comment" do
    test "goes out as the author when their login reaches the installation", %{poc: poc} do
      GitHubApp.seed_user_installations(poc, [7])
      stub_writes()

      case_record = open_linked_case(poc)
      post!(case_record, poc, "From me on GitHub", true)

      assert_received {:comment_write, written, headers}
      assert {"authorization", "Bearer gho_token"} in headers
      assert written["body"] =~ "From me on GitHub"
      refute written["body"] =~ "written by"
    end

    test "goes out as the App, naming the author, when their login does not reach it", %{
      poc: poc
    } do
      stub_writes()

      case_record = open_linked_case(poc)
      post!(case_record, poc, "Posted for me", true)

      assert_received {:comment_write, written, headers}
      assert {"authorization", "Bearer ghs_acme_lib"} in headers
      assert written["body"] =~ "Posted for me"
      assert written["body"] =~ "written by"
      assert written["body"] =~ "cross_post_poc name"
    end
  end

  describe "what the comment carries" do
    test "every body links back to the case", %{poc: poc} do
      stub_writes()

      case_record = open_linked_case(poc)
      post!(case_record, poc, "Read the rest here", true)

      assert_received {:comment_write, written, _headers}
      assert written["body"] =~ "/cases/#{case_record.id}"
      assert written["body"] =~ "Cross-posted from the EEF CNA case"
    end

    test "the stored comment keeps the address GitHub gave it", %{poc: poc} do
      stub_writes()

      case_record = open_linked_case(poc)
      comment = post!(case_record, poc, "Shared", true)

      assert to_string(comment.github_html_url) == "#{@url}#advisory-comment-9001"
      assert comment.source == :varsel
      assert comment.author_id == poc.id
    end
  end

  describe "when the poll reads the comment back" do
    # GitHub serves a cross-posted comment like any other, so without the id
    # it gave us the poll would store it a second time.
    defp stub_write_then_read(body) do
      written = :counters.new(1, [])

      GitHubApi.stub(fn conn ->
        case {conn.method, Enum.reverse(conn.path_info)} do
          {"POST", ["comments" | _rest]} ->
            :counters.add(written, 1, 1)
            answer_write(conn, 201)

          {_method, ["comments" | _rest]} ->
            Req.Test.json(conn, read_back(written, body))

          {_method, ["users", login]} ->
            Req.Test.json(conn, %{"login" => login, "name" => nil, "email" => nil})

          _advisory ->
            Req.Test.json(conn, hex_advisory())
        end
      end)
    end

    defp read_back(written, body) do
      if :counters.get(written, 1) > 0 do
        [
          %{
            "id" => 9001,
            "body" => body <> "\n\n<sub>[Cross-posted from the EEF CNA case](x)</sub>",
            "html_url" => "#{@url}#advisory-comment-9001",
            "created_at" => "2026-10-20T10:00:00Z",
            "updated_at" => "2026-10-20T10:00:00Z",
            "user" => %{"login" => "eef-cna-local", "id" => 99, "type" => "Bot"}
          }
        ]
      else
        []
      end
    end

    defp poll!(link, poc) do
      Cases.sync_github_advisory_comments!(
        Ash.reload!(link, actor: poc),
        actor: Varsel.Service.github_comment_sync()
      )
    end

    test "stores the id GitHub gave it, so the poll knows the comment", %{poc: poc} do
      stub_write_then_read("Shared outward")

      case_record = open_linked_case(poc)
      comment = post!(case_record, poc, "Shared outward", true)

      assert comment.github_comment_id == 9001
    end

    test "reading it back does not repeat it", %{poc: poc} do
      stub_write_then_read("Shared outward")

      {case_record, link} = open_linked_case_with_link(poc)
      post!(case_record, poc, "Shared outward", true)

      for _poll <- 1..3, do: poll!(link, poc)

      assert [only] = Cases.list_case_comments!(case_record.id, actor: poc)
      assert only.github_comment_id == 9001
    end

    test "keeps its author, its source and the body they wrote", %{poc: poc} do
      stub_write_then_read("Shared outward")

      {case_record, link} = open_linked_case_with_link(poc)
      post!(case_record, poc, "Shared outward", true)

      poll!(link, poc)

      assert [only] = Cases.list_case_comments!(case_record.id, actor: poc)
      assert only.author_id == poc.id
      assert only.source == :varsel
      # The footer the cross-post added is not the author's text.
      assert only.body == "Shared outward"
    end

    test "tells nobody about a comment of ours coming back", %{poc: poc} do
      supporter = Fixtures.register_user("cross_post_quiet", :supporter)

      stub_write_then_read("Shared outward")

      {case_record, link} = open_linked_case_with_link(poc)
      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)

      post!(case_record, poc, "Shared outward", true)
      for _poll <- 1..3, do: poll!(link, poc)

      AshOban.Test.schedule_and_run_triggers({Event, :fan_out})

      assert [%{count: 1}] = unread_comment_notifications(supporter)
    end
  end

  describe "when the author does not ask for it" do
    test "writes nothing to GitHub and stores the comment", %{poc: poc} do
      stub_writes()

      case_record = open_linked_case(poc)
      comment = post!(case_record, poc, "Just for us", false)

      refute_received {:comment_write, _written, _headers}
      assert comment.github_html_url == nil
      assert [stored] = Cases.list_case_comments!(case_record.id, actor: poc)
      assert stored.body == "Just for us"
    end

    test "a case with no advisory posts normally", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "No advisory here"})

      comment = post!(case_record, poc, "Local only", false)

      assert comment.body == "Local only"
    end
  end

  describe "when GitHub refuses" do
    test "nothing is stored, so the case never claims GitHub has it", %{poc: poc} do
      stub_writes(status: 500)

      case_record = open_linked_case(poc)

      assert {:error, error} =
               Cases.post_case_comment(
                 %{case_id: case_record.id, body: "Never landed", cross_post: true},
                 actor: poc
               )

      message = Exception.message(error)

      assert message =~ "GHSA-2cfg-hjmp-qrvw"
      assert message =~ "GitHub refused it. Nothing was posted"
      # GitHub's status and body are logged, never shown.
      refute message =~ ":http"
      assert Cases.list_case_comments!(case_record.id, actor: poc) == []
    end

    test "the same comment posts once the author unchecks it", %{poc: poc} do
      stub_writes(status: 500)

      case_record = open_linked_case(poc)

      assert {:error, _error} =
               Cases.post_case_comment(
                 %{case_id: case_record.id, body: "Landing here instead", cross_post: true},
                 actor: poc
               )

      comment = post!(case_record, poc, "Landing here instead", false)

      assert comment.body == "Landing here instead"
      assert [_one] = Cases.list_case_comments!(case_record.id, actor: poc)
    end

    test "asking to cross-post a case with no advisory is refused on the field", %{poc: poc} do
      case_record = Fixtures.open_case(poc, %{title: "No advisory here"})

      assert {:error, error} =
               Cases.post_case_comment(
                 %{case_id: case_record.id, body: "Nowhere to send it", cross_post: true},
                 actor: poc
               )

      assert Exception.message(error) =~ "no linked GitHub advisory"
      assert Cases.list_case_comments!(case_record.id, actor: poc) == []
    end
  end
end
