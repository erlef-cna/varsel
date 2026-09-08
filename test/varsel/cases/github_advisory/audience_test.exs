# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.AudienceTest do
  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisory.Audience
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"

  setup do
    poc = Fixtures.register_user("audience_poc", :poc)
    GitHubApi.stub_advisory(advisory_with_audience())
    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})

    link =
      Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @hex_url}, actor: poc)

    %{poc: poc, link: link}
  end

  defp advisory_with_audience do
    Map.merge(hex_advisory(), %{
      "collaborating_users" => [%{"login" => "alice"}],
      "collaborating_teams" => [%{"slug" => "security"}]
    })
  end

  defp stub_organization(answer) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      send(test_pid, {:github, conn.path_info, Plug.Conn.get_req_header(conn, "authorization")})
      answer.(conn)
    end)
  end

  test "lists the collaborators, each team's members and the organization's owners as the viewer",
       %{
         poc: poc,
         link: link
       } do
    stub_organization(fn conn ->
      case conn.path_info do
        ["orgs", "acme", "members"] ->
          Req.Test.json(conn, [%{"login" => "bob"}])

        ["orgs", "acme", "teams", "security", "members"] ->
          Req.Test.json(conn, [%{"login" => "carol"}, %{"login" => "dana"}])
      end
    end)

    assert Audience.resolve(link, poc) == %{
             users: ["alice"],
             teams: [%{slug: "security", members: ["carol", "dana"]}],
             owners: ["bob"]
           }

    assert_received {:github, ["orgs", "acme", "members"], ["Bearer gho_token"]}

    assert_received {:github, ["orgs", "acme", "teams", "security", "members"], ["Bearer gho_token"]}
  end

  test "a repository under a user account has that user as its owner", %{poc: poc, link: link} do
    stub_organization(fn conn ->
      case conn.path_info do
        ["orgs", "acme", "members"] -> Plug.Conn.send_resp(conn, 404, "{}")
        ["orgs", "acme", "teams", "security", "members"] -> Plug.Conn.send_resp(conn, 404, "{}")
      end
    end)

    assert %{owners: ["acme"], teams: [%{slug: "security", members: :unknown}]} =
             Audience.resolve(link, poc)
  end

  test "a group GitHub does not list to the viewer is unknown", %{poc: poc, link: link} do
    stub_organization(fn conn ->
      conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"message" => "Must have admin rights"})
    end)

    assert Audience.resolve(link, poc) == %{
             users: ["alice"],
             teams: [%{slug: "security", members: :unknown}],
             owners: :unknown
           }
  end

  test "a viewer without a GitHub account learns only the collaborators, and GitHub is not asked",
       %{
         link: link
       } do
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked without a token") end)
    hex_user = Fixtures.sign_in_with_hex("audience_hex", System.unique_integer([:positive]))

    unknown = %{
      users: ["alice"],
      teams: [%{slug: "security", members: :unknown}],
      owners: :unknown
    }

    assert Audience.resolve(link, hex_user) == unknown
    assert Audience.resolve(link, nil) == unknown
  end

  test "a global database entry names no organization to ask", %{poc: poc} do
    hex_advisory()
    |> Map.merge(%{
      "ghsa_id" => "GHSA-hjmp-qrvw-2cfg",
      "html_url" => "https://github.com/advisories/GHSA-hjmp-qrvw-2cfg",
      "collaborating_users" => [%{"login" => "alice"}],
      "collaborating_teams" => [%{"slug" => "security"}]
    })
    |> Map.delete("source_code_location")
    |> GitHubApi.stub_advisory()

    case_record = Fixtures.open_case(poc, %{title: "Global entry"})

    link =
      Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: "GHSA-hjmp-qrvw-2cfg"},
        actor: poc
      )

    GitHubApi.stub(fn _conn ->
      flunk("GitHub was asked about an organization the entry does not name")
    end)

    assert Audience.resolve(link, poc) == %{
             users: ["alice"],
             teams: [%{slug: "security", members: :unknown}],
             owners: :unknown
           }
  end
end
