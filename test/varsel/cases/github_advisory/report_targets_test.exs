# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubAdvisory.ReportTargetsTest do
  use Varsel.DataCase, async: false

  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.Cases.GitHubAdvisory.ReportTargets
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  setup do
    poc = Fixtures.register_user("targets_poc", :poc)
    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})

    %{poc: poc, case: case_record}
  end

  defp package(repo_url), do: %AffectedPackage{repo_url: repo_url && URI.new!(repo_url)}

  describe "repositories/1" do
    test "names each GitHub repository of the affected packages once, in package order" do
      case_record =
        struct!(Case,
          affected_packages: [
            package("https://github.com/acme/acme_lib"),
            package("https://gitlab.com/acme/other"),
            package(nil),
            package("https://github.com/acme/acme_lib.git"),
            package("https://github.com/erlang/otp/"),
            package("https://github.com/acme")
          ]
        )

      assert ReportTargets.repositories(case_record) == [
               %{owner: "acme", repo: "acme_lib"},
               %{owner: "erlang", repo: "otp"}
             ]
    end
  end

  describe "list/2" do
    test "asks GitHub as the viewer whether each repository takes private reports", %{
      poc: poc,
      case: case_record
    } do
      Fixtures.add_affected_package(poc, case_record)

      Fixtures.add_affected_package(poc, case_record, %{
        vendor: "erlang",
        product: "otp",
        repo_url: "https://github.com/erlang/otp",
        position: 1
      })

      test_pid = self()

      GitHubApi.stub(fn conn ->
        send(test_pid, {:github, conn.path_info, Plug.Conn.get_req_header(conn, "authorization")})

        case conn.path_info do
          ["repos", "acme", "acme_lib", "private-vulnerability-reporting"] ->
            Req.Test.json(conn, %{"enabled" => false})

          ["repos", "erlang", "otp", "private-vulnerability-reporting"] ->
            Req.Test.json(conn, %{"enabled" => true})
        end
      end)

      repositories =
        case_record.id
        |> Cases.get_case!(actor: poc, load: [affected_packages: [:repo_url]])
        |> ReportTargets.repositories()

      assert ReportTargets.list(repositories, poc) == [
               %{owner: "acme", repo: "acme_lib", private_reporting: false},
               %{owner: "erlang", repo: "otp", private_reporting: true}
             ]

      assert_received {:github, ["repos", "acme", "acme_lib", "private-vulnerability-reporting"], ["Bearer gho_token"]}
    end

    test "a repository GitHub does not answer for is unknown", %{poc: poc} do
      GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

      assert ReportTargets.list([%{owner: "acme", repo: "acme_lib"}], poc) == [
               %{owner: "acme", repo: "acme_lib", private_reporting: :unknown}
             ]
    end

    test "no repository asks GitHub nothing", %{poc: poc} do
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked about no repository") end)

      assert ReportTargets.list([], poc) == []
    end
  end
end
