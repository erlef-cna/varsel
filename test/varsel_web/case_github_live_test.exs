# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseGitHubLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Varsel.Test.GitHubAdvisoryFixtures

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @acme_lib 7
  @installation "Bearer ghs_acme_lib"

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

  # A link to an advisory on acme/other_lib, which no installation of the App
  # covers, so linking it through GitHub is not possible.
  defp seed_uninstalled_link!(case_record) do
    advisory = Map.put(hex_advisory(), "ghsa_id", "GHSA-4v2x-7mq8-w3rf")

    Ash.Seed.seed!(GitHubAdvisoryLink, %{
      case_id: case_record.id,
      ghsa_id: advisory["ghsa_id"],
      owner: "acme",
      repo: "other_lib",
      html_url: "https://github.com/acme/other_lib/security/advisories/#{advisory["ghsa_id"]}",
      state: :draft,
      title: advisory["summary"],
      advisory: advisory,
      fetched_at: DateTime.truncate(DateTime.utc_now(), :second)
    })
  end

  setup %{conn: conn} do
    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    GitHubApp.seed_installation(
      %{id: @acme_lib, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: "ghs_acme_lib"
    )

    poc = Fixtures.register_user("advisory_live_poc", :poc)
    GitHubApp.seed_user_installations(poc, [@acme_lib])
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
    render_async(lv)

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
    render_async(lv)

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
    render_async(lv)

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
    render_async(lv)

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
    GitHubApp.seed_user_installations(collaborator, [@acme_lib])
    assign!(case_record, collaborator, poc)
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)

    {:ok, lv, _html} = conn |> log_in(collaborator) |> live(~p"/cases/#{case_record.id}/github")

    refute has_element?(lv, "#link-advisory-form")
    assert has_element?(lv, "#link-advisory", "No advisory is linked to this case.")

    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(collaborator) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
    assert has_element?(lv, "#github-advisory button", "Refresh")
    refute has_element?(lv, "#github-advisory button", "Unlink")
    assert has_element?(lv, "#diff-title", "differs")
    refute has_element?(lv, "#advisory-diff button")
  end

  test "a POC without a GitHub identity acts as the App where it is installed", %{
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
    render_async(lv)

    refute has_element?(lv, "#github-identity-notice")
    assert has_element?(lv, "#github-advisory button", "Refresh")
    assert has_element?(lv, "#diff-title button", "Pull")
    assert has_element?(lv, "#diff-title button", "Push")

    uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
    seed_uninstalled_link!(uninstalled)

    {:ok, lv, _html} = conn |> log_in(hex_poc) |> live(~p"/cases/#{uninstalled.id}/github")
    render_async(lv)

    assert has_element?(lv, "#github-identity-notice")
    refute has_element?(lv, "#github-advisory button[phx-click='refresh_advisory']")
    refute has_element?(lv, "#diff-title button[phx-click='push_advisory']")
    assert has_element?(lv, "#github-advisory button", "Refresh with gh")
  end

  defp stub_reporting(enabled?) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["repos", owner, repo, "private-vulnerability-reporting"] ->
          send(test_pid, {:github, :reporting, "#{owner}/#{repo}"})
          Req.Test.json(conn, %{"enabled" => enabled?})

        ["repos", "acme", "acme_lib"] ->
          Req.Test.json(conn, %{"permissions" => %{"admin" => false}})

        ["repos", "acme", "acme_lib", "security-advisories", "reports"] ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)
          send(test_pid, {:github, :report, JSON.decode!(body)})
          conn |> Plug.Conn.put_status(201) |> Req.Test.json(hex_advisory())
      end
    end)
  end

  defp stub_audience(advisory) do
    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["orgs", "acme", "members"] ->
          Req.Test.json(conn, [%{"login" => "bob"}])

        ["orgs", "acme", "teams", "security", "members"] ->
          Req.Test.json(conn, [%{"login" => "carol"}, %{"login" => "advisory_live_dana"}])

        ["users", "alice"] ->
          Req.Test.json(conn, %{"login" => "alice", "name" => nil, "email" => nil})

        ["users", login] ->
          Req.Test.json(conn, %{
            "login" => login,
            "name" => nil,
            "email" => "#{login}@example.com"
          })

        _advisory ->
          Req.Test.json(conn, advisory)
      end
    end)
  end

  defp advisory_with_audience do
    Map.merge(hex_advisory(), %{
      "collaborating_users" => [%{"login" => "alice"}],
      "collaborating_teams" => [%{"slug" => "security"}]
    })
  end

  test "a repository that takes no private reports is warned about and not reported to", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Fixtures.add_affected_package(poc, case_record)
    stub_reporting(false)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    render_async(lv)

    assert_received {:github, :reporting, "acme/acme_lib"}

    assert has_element?(
             lv,
             "#reporting-disabled a[href='/maintainer-process#2-preferred-channel-github-private-vulnerability-reporting']"
           )

    assert has_element?(lv, "#report-advisory-form button[disabled]", "Report privately")
  end

  test "a case with no advisory is reported to one of its GitHub repositories", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Fixtures.add_affected_package(poc, case_record)
    stub_reporting(true)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#report-advisory-form option[value='acme/acme_lib']")
    assert has_element?(lv, "#report-advisory-form textarea[name='report[description]']")
    refute has_element?(lv, "#reporting-disabled")

    lv
    |> form("#report-advisory-form", %{
      "repository" => "acme/acme_lib",
      "report" => %{"description" => "For the maintainers."}
    })
    |> render_submit()

    render_async(lv)

    assert_received {:github, :report,
                     %{
                       "description" => "For the maintainers.",
                       "summary" => "Header injection in acme_lib"
                     }}

    assert has_element?(lv, "#flash-info", "Reported to the maintainers on GitHub.")
    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
    refute has_element?(lv, "#report-advisory")
  end

  test "an administrator of the repository opens a draft advisory instead", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Fixtures.add_affected_package(poc, case_record)

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["repos", "acme", "acme_lib", "private-vulnerability-reporting"] ->
          Req.Test.json(conn, %{"enabled" => true})

        ["repos", "acme", "acme_lib"] ->
          Req.Test.json(conn, %{"permissions" => %{"admin" => true}})

        ["repos", "acme", "acme_lib", "security-advisories"] ->
          conn |> Plug.Conn.put_status(201) |> Req.Test.json(hex_advisory())
      end
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    lv
    |> form("#report-advisory-form", %{
      "repository" => "acme/acme_lib",
      "report" => %{"description" => "For the maintainers."}
    })
    |> render_submit()

    render_async(lv)

    assert has_element?(lv, "#flash-info", "Opened a draft advisory on GitHub.")
    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
  end

  test "a report GitHub refuses is told on the form and links nothing", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Fixtures.add_affected_package(poc, case_record)

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["repos", "acme", "acme_lib", "private-vulnerability-reporting"] ->
          Req.Test.json(conn, %{"enabled" => true})

        ["repos", "acme", "acme_lib"] ->
          Req.Test.json(conn, %{"permissions" => %{"admin" => false}})

        _report ->
          conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"message" => "Not allowed"})
      end
    end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    lv
    |> form("#report-advisory-form", %{
      "repository" => "acme/acme_lib",
      "report" => %{"description" => "For the maintainers."}
    })
    |> render_submit()

    render_async(lv)

    assert has_element?(lv, "#report-advisory-form", "was refused by GitHub: Not allowed")
    refute has_element?(lv, "#github-advisory")
  end

  test "a case without a GitHub repository, a linked case and a frozen case offer no report", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    refute has_element?(lv, "#report-advisory")

    supporter = Fixtures.register_user("advisory_live_supporter", :supporter)
    assign!(case_record, supporter, poc)
    Fixtures.add_affected_package(poc, case_record)
    approve!(Cases.get_case!(case_record.id, actor: poc), poc)

    {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    refute has_element?(lv, "#report-advisory")

    linked = Fixtures.open_case(poc, %{title: "Linked case"})
    Fixtures.add_affected_package(poc, linked)
    GitHubApi.stub_advisory(hex_advisory())
    link!(linked, poc)
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{linked.id}/github")
    render_async(lv)

    refute has_element?(lv, "#report-advisory")
  end

  test "a POC without a GitHub identity reports as the App where it is installed", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    hex_poc = Fixtures.sign_in_with_hex("advisory_live_hex", "advisory_live_hex")
    hex_poc = Ash.update!(hex_poc, %{role: :poc}, action: :set_role, authorize?: false)
    Fixtures.add_affected_package(poc, case_record)
    stub_reporting(true)

    {:ok, lv, _html} = conn |> log_in(hex_poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#github-identity-notice")
    assert has_element?(lv, "#report-advisory button", "Open a draft advisory")
    assert has_element?(lv, "#report-as-app")

    uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})

    Fixtures.add_affected_package(poc, uninstalled, %{
      repo_url: "https://github.com/acme/other_lib"
    })

    {:ok, lv, _html} = conn |> log_in(hex_poc) |> live(~p"/cases/#{uninstalled.id}/github")
    render_async(lv)

    assert has_element?(lv, "#report-reach-notice", "This cannot be done from here")
    assert has_element?(lv, "#report-advisory button", "Report with gh")
    refute has_element?(lv, "#report-advisory button[disabled]")
  end

  test "who sees the advisory is resolved to people, marked against the case", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    dana = Fixtures.register_user("advisory_live_dana")
    assign!(case_record, dana, poc)
    stub_audience(advisory_with_audience())
    Cases.grant_case_access!(case_record, :github, "carol", actor: poc)
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#audience-alice button", "Give access")
    assert has_element?(lv, "#audience-bob button", "Give access")
    assert has_element?(lv, "#audience-carol", "invited")
    refute has_element?(lv, "#audience-carol button")
    assert has_element?(lv, "#audience-advisory_live_dana", "on the case")
    refute has_element?(lv, "#audience-advisory_live_dana button")
  end

  test "giving access assigns an account here and invites everyone else", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    bob = Fixtures.register_user("bob")
    stub_audience(advisory_with_audience())
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    lv |> element("#audience-bob button", "Give access") |> render_click()

    assert has_element?(lv, "#flash-info", "bob has access to the case.")
    assert has_element?(lv, "#audience-bob", "on the case")
    refute has_element?(lv, "#audience-bob button")

    lv |> element("#audience-alice button", "Give access") |> render_click()

    assert has_element?(lv, "#flash-info", "alice has access to the case.")
    assert has_element?(lv, "#audience-alice", "invited")
    refute has_element?(lv, "#audience-alice button")

    assignments = Cases.get_case!(case_record.id, actor: poc, load: [:assignments, :invites])
    assert Enum.any?(assignments.assignments, &(&1.user_id == bob.id))
    assert [%{strategy: :github, email_status: :skipped}] = assignments.invites
  end

  test "a collaborator who may not grant access sees the audience without buttons", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    collaborator = Fixtures.register_user("advisory_live_collaborator")
    GitHubApp.seed_user_installations(collaborator, [@acme_lib])
    assign!(case_record, collaborator, poc)
    stub_audience(advisory_with_audience())
    link!(case_record, poc)

    {:ok, lv, _html} = conn |> log_in(collaborator) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#audience-alice")
    assert has_element?(lv, "#audience-bob")
    refute has_element?(lv, "#advisory-audience button")
  end

  test "a frozen case links, pulls and unlinks nothing, and still refreshes and pushes", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    supporter = Fixtures.register_user("advisory_live_supporter", :supporter)
    GitHubApp.seed_user_installations(supporter, [@acme_lib])
    assign!(case_record, supporter, poc)
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)
    link!(case_record, poc)
    approve!(Cases.get_case!(case_record.id, actor: poc), poc)

    {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#github-advisory button", "Refresh")
    refute has_element?(lv, "#github-advisory button", "Unlink")
    assert has_element?(lv, "#diff-title button", "Push")
    refute has_element?(lv, "#diff-title button", "Pull")
    refute has_element?(lv, "#advisory-diff button", "Pull all")

    other = Fixtures.open_case(poc, %{title: "Approved case"})
    assign!(other, supporter, poc)
    approve!(other, poc)

    {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{other.id}/github")

    refute has_element?(lv, "#link-advisory-form")
    assert has_element?(lv, "#link-advisory", "No advisory is linked to this case.")
  end

  test "a POC still links, pulls and unlinks on an approved case", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Working title"}, actor: poc)
    link!(case_record, poc)
    approve!(Cases.get_case!(case_record.id, actor: poc), poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

    assert has_element?(lv, "#github-advisory button", "Unlink")
    assert has_element?(lv, "#diff-title button", "Pull")

    other = Fixtures.open_case(poc, %{title: "Approved case"})
    approve!(other, poc)

    {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{other.id}/github")

    assert has_element?(lv, "#link-advisory-form")
  end

  describe "what the viewer's GitHub login reaches" do
    setup %{poc: poc, case: case_record} do
      Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)
      link!(case_record, poc)
      :ok
    end

    test "a supporter whose login does not reach the repository is told and offered neither", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      supporter = Fixtures.register_user("advisory_live_unreached", :supporter)
      assign!(case_record, supporter, poc)
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      assert has_element?(
               lv,
               "#github-reach-notice",
               "Your GitHub login cannot act on this repository."
             )

      assert has_element?(
               lv,
               "#github-reach-notice a[href='/settings/account']",
               "Account settings"
             )

      assert has_element?(lv, "#github-reach-notice", "show where the app can act for you")
      refute has_element?(lv, "#github-identity-notice")
      refute has_element?(lv, "#github-advisory button", "Refresh")
      refute has_element?(lv, "#diff-title button", "Push")
    end

    test "a GitHub access that does not renew is reported, and offers neither", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      supporter =
        "advisory_live_expired"
        |> Fixtures.sign_in_with_github(System.unique_integer([:positive]), %{
          "access_token" => "ghu_expiring",
          "expires_in" => 60
        })
        |> Ash.update!(%{role: :supporter}, action: :set_role, authorize?: false)

      GitHubApp.seed_user_installations(supporter, [@acme_lib])
      assign!(case_record, supporter, poc)
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      assert has_element?(
               lv,
               "#github-reach-notice",
               "This page needs you to sign in with GitHub again."
             )

      refute has_element?(lv, "#github-advisory button", "Refresh")
      refute has_element?(lv, "#diff-title button", "Push")
    end

    test "a POC is told when the App is not on the repository", %{conn: conn, poc: poc} do
      uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
      seed_uninstalled_link!(uninstalled)
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{uninstalled.id}/github")
      render_async(lv)

      assert has_element?(lv, "#github-reach-notice", "This cannot be done from here")
      refute has_element?(lv, "#github-advisory button[phx-click='refresh_advisory']")
      refute has_element?(lv, "#diff-title button[phx-click='push_advisory']")
    end

    test "a token the App cannot mint is reported on the click", %{conn: conn} do
      poc = Fixtures.register_user("advisory_live_unminted_poc", :poc)
      case_record = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
      GitHubApp.seed_installation(%{id: 8, account: "acme"}, repositories: ["acme/other_lib"])
      seed_uninstalled_link!(case_record)

      GitHubApi.stub(fn
        %{method: "POST", path_info: ["app", "installations", "8", "access_tokens"]} = conn ->
          Plug.Conn.send_resp(conn, 502, "{}")

        conn ->
          flunk("GitHub was asked #{conn.method} #{conn.request_path}")
      end)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      refute has_element?(lv, "#github-reach-notice")
      lv |> element("#github-advisory button", "Refresh") |> render_click()
      render_async(lv)

      assert has_element?(lv, "#flash-error", "could not reach GitHub")
      assert has_element?(lv, "#github-advisory", "GHSA-4v2x-7mq8-w3rf")
    end

    test "a POC whose login does not reach the repository pushes as the App", %{
      conn: conn,
      case: case_record
    } do
      poc = Fixtures.register_user("advisory_live_unreached_poc", :poc)
      test_pid = self()

      GitHubApi.stub(fn conn ->
        send(test_pid, {:github, conn.method, Plug.Conn.get_req_header(conn, "authorization")})

        Req.Test.json(
          conn,
          Map.put(hex_advisory(), "summary", "Header injection in acme_lib, revised")
        )
      end)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      refute has_element?(lv, "#github-reach-notice")
      lv |> element("#diff-title button", "Push") |> render_click()
      render_async(lv)

      assert_received {:github, "PATCH", [@installation]}
      assert has_element?(lv, "#flash-info", "Pushed to the advisory.")
      assert has_element?(lv, "#diff-title", "same")
    end
  end

  test "a POC whose login does not reach the repository opens a draft as the App", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    unreached_poc = Fixtures.register_user("advisory_live_report_unreached_poc", :poc)
    Fixtures.add_affected_package(poc, case_record)
    test_pid = self()

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["repos", "acme", "acme_lib", "private-vulnerability-reporting"] ->
          Req.Test.json(conn, %{"enabled" => false})

        ["repos", "acme", "acme_lib", "security-advisories"] ->
          send(test_pid, {:github, :draft, Plug.Conn.get_req_header(conn, "authorization")})
          conn |> Plug.Conn.put_status(201) |> Req.Test.json(hex_advisory())
      end
    end)

    {:ok, lv, _html} = conn |> log_in(unreached_poc) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(lv, "#report-as-app")
    refute has_element?(lv, "#reporting-disabled")

    lv
    |> form("#report-advisory-form", %{
      "repository" => "acme/acme_lib",
      "report" => %{"description" => "For the maintainers."}
    })
    |> render_submit()

    render_async(lv)

    assert_received {:github, :draft, [@installation]}
    assert has_element?(lv, "#flash-info", "Opened a draft advisory on GitHub.")
    assert has_element?(lv, "#github-advisory", "GHSA-2cfg-hjmp-qrvw")
  end

  test "a supporter is told a repository their login cannot report to", %{
    conn: conn,
    poc: poc,
    case: case_record
  } do
    supporter = Fixtures.register_user("advisory_live_report_unreached", :supporter)
    assign!(case_record, supporter, poc)
    Fixtures.add_affected_package(poc, case_record)
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)

    {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{case_record.id}/github")
    render_async(lv)

    assert has_element?(
             lv,
             "#report-reach-notice",
             "Your GitHub login cannot act on this repository."
           )

    assert has_element?(lv, "#report-advisory-form button[disabled]", "Report privately")
  end

  describe "a request done with gh where the App is not installed" do
    @other_lib_ghsa "GHSA-4v2x-7mq8-w3rf"
    @other_lib_url "https://github.com/acme/other_lib/security/advisories/#{@other_lib_ghsa}"

    setup do
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked about a repository") end)
      :ok
    end

    defp other_lib_answer(overrides \\ %{}) do
      hex_advisory()
      |> Map.merge(%{"ghsa_id" => @other_lib_ghsa, "html_url" => @other_lib_url})
      |> Map.merge(overrides)
    end

    # The command is syntax-highlighted, and the test DOM drops the whitespace
    # between the highlighted tokens, so the text is compared without it.
    defp command(lv) do
      lv
      |> element("#gh-command-text pre")
      |> render()
      |> LazyHTML.from_fragment()
      |> LazyHTML.text()
      |> without_whitespace()
    end

    defp without_whitespace(text), do: String.replace(text, ~r/\s+/, "")

    defp command_parts(command) do
      [_all, token] = Regex.run(~r/Bearer([A-Za-z0-9_.-]+)"/, command)
      [_all, id] = Regex.run(~r{/api/github/manual/([0-9a-f-]+)/result}, command)
      %{token: token, id: id}
    end

    defp post_answer(%{token: token, id: id}, answer) do
      build_conn()
      |> put_req_header("authorization", "Bearer #{token}")
      |> put_req_header("content-type", "application/json")
      |> post(~p"/api/github/manual/#{id}/result", JSON.encode!(answer))
      |> json_response(200)
    end

    defp occurrences(text, part), do: length(String.split(text, part)) - 1

    test "is offered to a POC, and not to a supporter or where the App is installed", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
      seed_uninstalled_link!(uninstalled)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{uninstalled.id}/github")
      render_async(lv)

      assert has_element?(lv, "#github-reach-notice", "Do it with gh instead")
      assert has_element?(lv, "#github-advisory button", "Refresh with gh")
      assert has_element?(lv, "#diff-title button", "Push with gh")
      assert has_element?(lv, "#advisory-diff button", "Push all with gh")

      supporter = Fixtures.register_user("advisory_live_gh_supporter", :supporter)
      assign!(uninstalled, supporter, poc)

      {:ok, lv, _html} = conn |> log_in(supporter) |> live(~p"/cases/#{uninstalled.id}/github")
      render_async(lv)

      refute has_element?(lv, "#github-advisory button", "Refresh with gh")
      refute has_element?(lv, "#diff-title button", "Push with gh")

      GitHubApi.stub_advisory(hex_advisory())
      Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)
      link!(case_record, poc)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      refute has_element?(lv, "#github-advisory button", "Refresh with gh")
      assert has_element?(lv, "#diff-title button", "Push")
      refute has_element?(lv, "#diff-title button", "Push with gh")
    end

    test "the command carries the request and the token, which the page shows nowhere else", %{
      conn: conn,
      poc: poc
    } do
      uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
      seed_uninstalled_link!(uninstalled)
      path = "/repos/acme/other_lib/security-advisories/#{@other_lib_ghsa}"

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{uninstalled.id}/github")
      render_async(lv)

      lv |> element("#github-advisory button", "Refresh with gh") |> render_click()
      read = command(lv)
      %{token: token, id: id} = command_parts(read)

      assert String.starts_with?(
               read,
               without_whitespace("gh api #{path} \\\n  | curl -sS --fail-with-body")
             )

      assert occurrences(read, token) == 1
      assert occurrences(render(lv), token) == 1
      assert has_element?(lv, "#gh-command", "valid for 15 minutes")

      assert {:ok, %{"jti" => jti, "request_id" => ^id}} = AshAuthentication.Jwt.peek(token)
      assert Cases.get_github_manual_request!(id, actor: poc).token_id == jti

      lv |> element("#gh-command button", "Close") |> render_click()
      refute has_element?(lv, "#gh-command")

      lv |> element("#diff-title button", "Push with gh") |> render_click()
      push = command(lv)
      %{token: push_token} = command_parts(push)

      assert String.starts_with?(
               push,
               without_whitespace("curl -sf -H \"Authorization: Bearer #{push_token}\"")
             )

      assert push =~ without_whitespace("| gh api -X PATCH #{path} --input - \\\n")
      assert occurrences(push, push_token) == 2
      assert occurrences(render(lv), push_token) == 2
      refute push_token == token

      lv |> element("#gh-command button", "Close") |> render_click()
      lv |> element("#advisory-diff button", "Read again and pull all with gh") |> render_click()

      assert String.starts_with?(command(lv), without_whitespace("gh api #{path}"))
      assert has_element?(lv, "#gh-command", "reads #{@other_lib_ghsa} again and pulls Title")
    end

    test "the page closes the command and shows the advisory once GitHub's answer is posted", %{
      conn: conn,
      poc: poc
    } do
      uninstalled = Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
      seed_uninstalled_link!(uninstalled)

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{uninstalled.id}/github")
      render_async(lv)

      lv |> element("#github-advisory button", "Refresh with gh") |> render_click()
      parts = lv |> command() |> command_parts()

      assert %{"ok" => true} =
               post_answer(parts, other_lib_answer(%{"summary" => "Revised on GitHub"}))

      html = render(lv)
      refute html |> LazyHTML.from_document() |> LazyHTML.query("#gh-command") |> Enum.any?()
      assert has_element?(lv, "#flash-info", "GitHub's answer arrived and is recorded.")
      assert has_element?(lv, "#github-advisory", "Revised on GitHub")
    end

    test "a refused link offers to link with gh", %{conn: conn, poc: poc, case: case_record} do
      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")

      lv |> form("#link-advisory-form", form: %{advisory_url: @other_lib_url}) |> render_submit()

      assert has_element?(lv, "#link-advisory-form", "the EEF CNA app is not installed")

      lv |> element("#gh-link-offer button", "Link with gh") |> render_click()
      read = command(lv)

      assert String.starts_with?(
               read,
               without_whitespace("gh api /repos/acme/other_lib/security-advisories/#{@other_lib_ghsa}")
             )

      assert %{"ok" => true} = read |> command_parts() |> post_answer(other_lib_answer())

      render(lv)
      assert has_element?(lv, "#github-advisory", @other_lib_ghsa)
      refute has_element?(lv, "#gh-command")
    end

    test "a report to a repository without the App is offered as a draft or a private report", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      Fixtures.add_affected_package(poc, case_record, %{
        repo_url: "https://github.com/acme/other_lib"
      })

      {:ok, lv, _html} = conn |> log_in(poc) |> live(~p"/cases/#{case_record.id}/github")
      render_async(lv)

      assert has_element?(lv, "#report-gh-kind input[value='draft'][checked]")
      refute has_element?(lv, "#report-advisory-form button", "Report privately")

      lv
      |> form("#report-advisory-form", %{
        "repository" => "acme/other_lib",
        "gh_kind" => "report",
        "report" => %{"description" => "For the maintainers."}
      })
      |> render_submit(%{"via" => "gh"})

      report = command(lv)
      parts = command_parts(report)

      assert report =~
               without_whitespace("| gh api -X POST /repos/acme/other_lib/security-advisories/reports --input - \\\n")

      assert has_element?(
               lv,
               "#gh-command",
               "reports the case privately to the maintainers of acme/other_lib"
             )

      assert %{
               "description" => "For the maintainers.",
               "summary" => "Header injection in acme_lib"
             } =
               build_conn()
               |> put_req_header("authorization", "Bearer #{parts.token}")
               |> get(~p"/api/github/manual/#{parts.id}/request")
               |> json_response(200)

      assert %{"ok" => true} = post_answer(parts, other_lib_answer())

      render(lv)
      assert has_element?(lv, "#github-advisory", @other_lib_ghsa)
    end
  end
end
