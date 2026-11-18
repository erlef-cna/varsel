# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GitHubAdvisorySubmissionLiveTest do
  @moduledoc """
  The `/report` step where a maintainer submits their advisory by its
  address, and what it asks when the EEF CNA app does not reach them.
  """

  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import Varsel.Test.GitHubAdvisoryFixtures

  alias AshAuthentication.Plug.Helpers, as: AuthPlug
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  @url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"

  setup do
    Fixtures.register_user("advisory_live_poc", :poc)
    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: "ghs_acme_lib"
    )

    :ok
  end

  defp log_in(conn, user) do
    conn
    |> init_test_session(%{})
    |> AuthPlug.store_in_session(user)
  end

  defp stub_advisory do
    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["users", login] ->
          Req.Test.json(conn, %{"login" => login, "name" => nil, "email" => nil})

        _advisory ->
          Req.Test.json(conn, hex_advisory())
      end
    end)
  end

  defp stub_github_unreachable do
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked for a login the app does not reach") end)
  end

  defp submit_url(lv) do
    lv
    |> form("#github-advisory-form", %{"advisory" => %{"advisory_url" => @url}})
    |> render_submit()
  end

  test "a maintainer the app reaches submits the advisory and lands on the case", %{conn: conn} do
    maintainer = Fixtures.register_user("advisory_live_maintainer")
    GitHubApp.seed_user_installations(maintainer, [7])
    stub_advisory()

    {:ok, lv, _html} = conn |> log_in(maintainer) |> live(~p"/report/maintainer")

    lv |> element("#report-step-maintainer-yes") |> render_click()
    assert_patched(lv, ~p"/report/advisory")

    submit_url(lv)

    {path, flash} = assert_redirect(lv)
    assert flash["info"] =~ "has your advisory"

    [case_record] = Varsel.Cases.list_cases!(actor: maintainer)
    assert path == ~p"/cases/#{case_record.id}"
    assert case_record.state == :submitted
  end

  test "a login the app does not reach is asked whether they may install it", %{conn: conn} do
    stranger = Fixtures.register_user("advisory_live_stranger")
    stub_github_unreachable()

    {:ok, lv, _html} = conn |> log_in(stranger) |> live(~p"/report/advisory")

    submit_url(lv)

    assert has_element?(lv, "#report-app-question")
    refute has_element?(lv, "#report-github-app")
    assert Varsel.Cases.list_cases!(actor: stranger) == []
  end

  test "a yes shows where to install the app, and the next submit goes to the action", %{
    conn: conn
  } do
    stranger = Fixtures.register_user("advisory_live_installer")
    stub_github_unreachable()

    {:ok, lv, _html} = conn |> log_in(stranger) |> live(~p"/report/advisory")

    submit_url(lv)
    lv |> element("#report-app-question-yes") |> render_click()

    assert has_element?(lv, "#report-github-app #report-github-app-install")
    assert has_element?(lv, "#report-github-installations-refresh")

    submit_url(lv)

    assert lv |> element("#github-advisory-form") |> render() =~
             "needs to install the EEF CNA app"
  end

  test "a no asks to add the CNA to the advisory and carries its address into the report", %{
    conn: conn
  } do
    stranger = Fixtures.register_user("advisory_live_collaborator")
    stub_github_unreachable()

    {:ok, lv, _html} = conn |> log_in(stranger) |> live(~p"/report/advisory")

    submit_url(lv)
    lv |> element("#report-app-question-no") |> render_click()

    assert_patched(lv, ~p"/report/collaborators?#{[advisory_url: @url]}")

    assert has_element?(
             lv,
             "#report-poc-handle-advisory_live_poc a[href='https://github.com/advisory_live_poc']"
           )

    refute has_element?(lv, "#report-poc-handle-advisory_live_collaborator")
    assert has_element?(lv, "#vulnerability-report-form #form_advisory_url[value='#{@url}']")
  end

  test "an account without a GitHub login is sent to link one first", %{conn: conn} do
    user = Fixtures.sign_in_with_hex("advisory_live_hex", System.unique_integer([:positive]))
    stub_github_unreachable()

    {:ok, lv, _html} = conn |> log_in(user) |> live(~p"/report/advisory")

    submit_url(lv)
    lv |> element("#report-app-question-yes") |> render_click()

    assert has_element?(lv, "#report-github-unlinked a[href='/settings/account']")
    assert has_element?(lv, "#github-advisory-form button[type='submit'][disabled]")
  end
end
