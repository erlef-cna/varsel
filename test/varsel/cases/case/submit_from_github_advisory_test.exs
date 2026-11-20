# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.SubmitFromGitHubAdvisoryTest do
  @moduledoc """
  A maintainer submitting the GitHub advisory they hold: the case it opens,
  whose token reads the advisory, and which advisories it takes.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi
  alias Varsel.Test.GitHubApp

  require Ash.Query

  @url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @path "/repos/acme/acme_lib/security-advisories/GHSA-2cfg-hjmp-qrvw"

  @loads [:weaknesses, :credits, :affected_packages, :github_advisory_link, :assignments]

  setup do
    poc = Fixtures.register_user("submit_advisory_poc", :poc)
    maintainer = Fixtures.register_user("submit_advisory_maintainer")

    GitHubApp.seed_installation(%{id: 1, account: "erlef-cna"}, token: "ghs_erlef_cna")

    GitHubApp.seed_installation(%{id: 7, account: "acme", repository_selection: :selected},
      repositories: ["acme/acme_lib"],
      token: "ghs_acme_lib"
    )

    GitHubApp.seed_user_installations(maintainer, [7])

    %{poc: poc, maintainer: maintainer}
  end

  defp stub_advisory(advisory) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        ["users", login] ->
          Req.Test.json(conn, %{"login" => login, "name" => nil, "email" => nil})

        _advisory ->
          send(
            test_pid,
            {:github, conn.request_path, Plug.Conn.get_req_header(conn, "authorization")}
          )

          Req.Test.json(conn, advisory)
      end
    end)
  end

  defp stub_github_unreachable do
    GitHubApi.stub(fn _conn -> flunk("GitHub was contacted before the caller was refused") end)
  end

  defp submit(actor, url \\ @url) do
    Cases.submit_github_advisory(%{advisory_url: url}, actor: actor, load: @loads)
  end

  test "opens a submitted case with the advisory's title and link, read with the maintainer's own token",
       %{
         maintainer: maintainer
       } do
    stub_advisory(hex_advisory())

    assert {:ok, case_record} = submit(maintainer)

    assert_received {:github, @path, ["Bearer gho_token"]}

    assert case_record.state == :submitted
    assert case_record.accepted_at == nil
    assert case_record.title == "Header injection in acme_lib"
    assert case_record.github_advisory_link.ghsa_id == "GHSA-2cfg-hjmp-qrvw"

    assert [%{user_id: user_id, note: "Submitted the advisory as a maintainer"}] =
             case_record.assignments

    assert user_id == maintainer.id
  end

  test "writes nothing else of the advisory to the case", %{maintainer: maintainer} do
    stub_advisory(hex_advisory())

    assert {:ok, case_record} = submit(maintainer)

    assert case_record.description_md == nil
    assert Ash.load!(case_record, [:metrics], authorize?: false).metrics == []
    assert case_record.date_public == nil
    assert case_record.weaknesses == []
    assert case_record.credits == []
    assert case_record.affected_packages == []
  end

  test "tells the POCs about the submission", %{maintainer: maintainer, poc: poc} do
    stub_advisory(hex_advisory())

    {:ok, case_record} = submit(maintainer)
    Oban.drain_queue(queue: :default)

    assert [%{case_id: case_id}] =
             Varsel.Notifications.Notification
             |> Ash.Query.filter(kind == :report_submitted)
             |> Ash.read!(actor: poc)

    assert case_id == case_record.id
  end

  test "a login the app does not reach on the repository opens nothing" do
    stub_github_unreachable()
    stranger = Fixtures.register_user("submit_advisory_stranger")

    assert {:error, %Invalid{errors: [error]}} = submit(stranger)

    assert error.field == :advisory_url
  end

  test "a global database entry is refused before GitHub is asked", %{maintainer: maintainer} do
    stub_github_unreachable()

    for url <- ["GHSA-2cfg-hjmp-qrvw", "https://github.com/advisories/GHSA-2cfg-hjmp-qrvw"] do
      assert {:error, %Invalid{errors: [error]}} = submit(maintainer, url)
      assert error.field == :advisory_url
      assert error.message =~ "on its repository"
    end
  end

  test "an advisory another case holds is refused", %{maintainer: maintainer} do
    stub_advisory(hex_advisory())
    {:ok, _first} = submit(maintainer)

    assert {:error, %Invalid{errors: [error]}} = submit(maintainer)
    assert error.field == :advisory_url
  end

  test "nobody signed in is refused before GitHub is asked" do
    stub_github_unreachable()

    assert {:error, %Forbidden{}} = submit(nil)
  end
end
