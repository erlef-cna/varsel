# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseGitHubLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Varsel.Test.GitHubAdvisoryFixtures

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp link!(case_record, actor) do
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @hex_url}, actor: actor)
  end

  defp approve!(case_record, poc) do
    case_record |> Cases.request_case_review!(actor: poc) |> Cases.approve_case!(actor: poc)
  end

  defp assign!(case_record, user, poc) do
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: user.id}, actor: poc)
  end

  defp stub_patch(answer) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      send(test_pid, {:github, conn.method, JSON.decode!(body)})
      Req.Test.json(conn, answer)
    end)
  end

  setup %{conn: conn} do
    poc = Fixtures.register_user("advisory_live_poc", :poc)
    GitHubApi.stub_advisory(hex_advisory())

    %{
      conn: conn,
      poc: poc,
      case: Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})
    }
  end

  test "the tab sits next to the workspace and marks itself", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, ~s(a[href="/cases/#{case_record.id}"]), "Workspace")

    assert lv |> element(~s(a[href="/cases/#{case_record.id}/github"] span)) |> render() =~
             "font-bold"
  end

  test "links an advisory from the form and shows it against the case", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#link-advisory-form")
    refute has_element?(lv, "#github-advisory")

    lv |> form("#link-advisory-form", form: %{advisory_url: @hex_url}) |> render_submit()

    assert has_element?(lv, "#flash-info", "Linked GHSA-2cfg-hjmp-qrvw.")
    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
    assert has_element?(lv, "#github-advisory", "acme/acme_lib")
    assert has_element?(lv, "#advisory-diff th", "Case")
    assert has_element?(lv, "#diff-title", "same")
    assert has_element?(lv, "#diff-affected-0", "erlang/acme_lib")
    refute has_element?(lv, "#link-advisory-form")
  end

  test "a refused link is reported on the field and nothing changes", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    lv |> form("#link-advisory-form", form: %{advisory_url: @hex_url}) |> render_submit()

    assert has_element?(lv, "#link-advisory-form", "names no advisory you can see on GitHub")
    refute has_element?(lv, "#github-advisory")
  end

  test "refresh reads the advisory again", %{conn: conn, poc: poc, case: case_record} do
    link!(case_record, poc)

    GitHubApi.stub(&Req.Test.json(&1, Map.put(hex_advisory(), "summary", "Header injection, revised")))

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    lv |> element("#github-advisory button", "Refresh") |> render_click()
    render_async(lv)

    assert has_element?(lv, "#flash-info", "Advisory read again.")
    assert has_element?(lv, "#github-advisory", "Header injection, revised")
  end

  test "a row the advisory can add to is pulled from the table", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#advisory-diff button", "Pull all")
    assert has_element?(lv, "#diff-title", "differs")

    lv |> element("#diff-title button", "Pull") |> render_click()

    assert has_element?(lv, "#flash-info", "Pulled Title from the advisory.")
    assert Cases.get_case!(case_record.id, actor: poc).title == "Header injection in acme_lib"
    assert has_element?(lv, "#diff-title", "same")
    refute has_element?(lv, "#diff-title button", "Pull")
  end

  test "every row the advisory can add to is pulled at once", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Fixtures.seed_weakness(113, "Improper Neutralization of CRLF Sequences in HTTP Headers")
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#diff-weaknesses", "GitHub only")
    assert has_element?(lv, "#diff-credits", "GitHub only")

    lv |> element("#advisory-diff button", "Pull all") |> render_click()

    assert has_element?(
             lv,
             "#flash-info",
             "Pulled Title, CWEs, Credits, Affected packages from the advisory."
           )

    assert has_element?(lv, "#diff-title", "same")
    assert has_element?(lv, "#diff-weaknesses", "same")
    assert has_element?(lv, "#diff-credits", "same")
    assert has_element?(lv, "#diff-affected-0", "not derived")
    refute has_element?(lv, "#advisory-diff button", "Pull all")
  end

  test "a row the case can write is pushed from the table", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)
    link!(case_record, poc)
    stub_patch(Map.put(hex_advisory(), "summary", "Header injection in acme_lib, revised"))

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#advisory-diff button", "Push all")

    lv |> element("#diff-title button", "Push") |> render_click()
    render_async(lv)

    assert_received {:github, "PATCH", %{"summary" => "Header injection in acme_lib, revised"}}
    assert has_element?(lv, "#flash-info", "Pushed to the advisory.")
    assert has_element?(lv, "#diff-title", "same")
    refute has_element?(lv, "#diff-title button", "Push")
  end

  test "a push names the credited people the advisory cannot state", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    bob = Fixtures.register_user("advisory_live_bob")

    Cases.add_case_credit!(
      %{case_id: case_record.id, name: "Bob", credit_type: :analyst, user_id: bob.id},
      actor: poc
    )

    Cases.add_case_credit!(
      %{case_id: case_record.id, name: "Nobody Here", credit_type: :reporter},
      actor: poc
    )

    link!(case_record, poc)
    stub_patch(hex_advisory())

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    lv |> element("#diff-credits button", "Push") |> render_click()
    render_async(lv)

    assert_received {:github, "PATCH", %{"credits" => credits}}
    assert %{"login" => "advisory_live_bob", "type" => "analyst"} in credits

    assert has_element?(
             lv,
             "#flash-info",
             "Pushed to the advisory. Not stated, having no GitHub account here: Nobody Here."
           )
  end

  test "a refusal from GitHub is reported and nothing changes", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)
    link!(case_record, poc)

    GitHubApi.stub(fn conn ->
      conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"message" => "Not allowed"})
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    lv |> element("#diff-title button", "Push") |> render_click()
    render_async(lv)

    assert has_element?(lv, "#flash-error", "was refused by GitHub: Not allowed")
    assert has_element?(lv, "#diff-title button", "Push")
  end

  test "unlink removes the advisory and offers the form again", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    lv |> element("#github-advisory button", "Unlink") |> render_click()

    assert has_element?(lv, "#flash-info", "Unlinked GHSA-2cfg-hjmp-qrvw.")
    assert has_element?(lv, "#link-advisory-form")
    refute has_element?(lv, "#github-advisory")
  end

  test "an assigned collaborator without a role sees the advisory but no way to change it", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    collaborator = Fixtures.register_user("advisory_live_collaborator")
    assign!(case_record, collaborator, poc)
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

    {:ok, lv, _html} = conn |> log_in(collaborator) |> live(~p"/cases/#{case_record.id}/github")

    refute has_element?(lv, "#link-advisory-form")
    assert has_element?(lv, "#link-advisory", "No advisory is linked to this case.")

    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(collaborator) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
    assert has_element?(lv, "#github-advisory button", "Refresh")
    refute has_element?(lv, "#github-advisory button", "Unlink")
    assert has_element?(lv, "#diff-title", "differs")
    refute has_element?(lv, "#advisory-diff button")
  end

  test "a viewer without a GitHub identity is told, and neither refreshes nor pushes", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    hex_poc = Fixtures.sign_in_with_hex("advisory_live_hex", "advisory_live_hex")
    hex_poc = Ash.update!(hex_poc, %{role: :poc}, action: :set_role, authorize?: false)
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

    {:ok, lv, _html} = conn |> log_in(hex_poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#github-identity-notice a[href='/settings/account']")
    assert has_element?(lv, "#link-advisory-form")

    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(hex_poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#github-advisory")
    refute has_element?(lv, "#github-advisory button", "Refresh")
    assert has_element?(lv, "#diff-title button", "Pull")
    refute has_element?(lv, "#diff-title button", "Push")
    refute has_element?(lv, "#advisory-diff button", "Push all")

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    refute has_element?(lv, "#github-identity-notice")
    assert has_element?(lv, "#github-advisory button", "Refresh")
    assert has_element?(lv, "#diff-title button", "Push")
  end

  test "a frozen case links, pulls and unlinks nothing, and still refreshes and pushes", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)
    link!(case_record, poc)
    approve!(Cases.get_case!(case_record.id, actor: poc), poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#github-advisory button", "Refresh")
    refute has_element?(lv, "#github-advisory button", "Unlink")
    assert has_element?(lv, "#diff-title button", "Push")
    refute has_element?(lv, "#diff-title button", "Pull")
    refute has_element?(lv, "#advisory-diff button", "Pull all")

    other = Fixtures.open_case(poc, %{title: "Approved case"})
    approve!(other, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{other.id}/github")

    refute has_element?(lv, "#link-advisory-form")
    assert has_element?(lv, "#link-advisory", "No advisory is linked to this case.")
  end
end
