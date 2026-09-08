# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Case.Changes.ReportToGitHubTest do
  @moduledoc """
  Reporting a case to a repository's maintainers: what goes to GitHub, what
  the case keeps of the answer, and who may.
  """

  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias Varsel.Cases
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @report %{owner: "acme", repo: "acme_lib", description: "Written for the maintainers."}
  @loads [:references, :derived_references, :github_advisory_link]
  @repository_path ["repos", "acme", "acme_lib"]
  @report_path "/repos/acme/acme_lib/security-advisories/reports"
  @draft_path "/repos/acme/acme_lib/security-advisories"

  setup do
    poc = Fixtures.register_user("report_poc", :poc)
    Fixtures.seed_weakness(113, "Improper Neutralization of CRLF Sequences in HTTP Headers")

    case_record = Fixtures.open_case(poc, %{title: "Header injection in acme_lib"})
    Cases.add_case_weakness!(%{case_id: case_record.id, cwe_id: 113}, actor: poc)
    Fixtures.add_affected_package(poc, case_record)

    %{poc: poc, case: Cases.get_case!(case_record.id, actor: poc)}
  end

  defp report(case_record, actor, opts \\ []) do
    Cases.report_case_to_github(case_record, @report, Keyword.put(opts, :actor, actor))
  end

  defp stub_github(admin?, answer) do
    test_pid = self()

    GitHubApi.stub(fn conn ->
      case conn.path_info do
        @repository_path ->
          Req.Test.json(conn, %{"permissions" => %{"admin" => admin?}})

        _write ->
          {:ok, body, conn} = Plug.Conn.read_body(conn)

          send(
            test_pid,
            {:github, conn.method, conn.request_path, Plug.Conn.get_req_header(conn, "authorization"), JSON.decode!(body)}
          )

          answer.(conn)
      end
    end)
  end

  defp stub_report(admin? \\ false) do
    stub_github(admin?, &(&1 |> Plug.Conn.put_status(201) |> Req.Test.json(hex_advisory())))
  end

  defp stub_refusal(admin?, status, body) do
    stub_github(admin?, &(&1 |> Plug.Conn.put_status(status) |> Req.Test.json(body)))
  end

  defp stub_github_unreachable do
    GitHubApi.stub(fn _conn -> flunk("GitHub was contacted before the caller was refused") end)
  end

  defp assert_unlinked(case_record, poc) do
    assert Cases.get_case!(case_record.id, actor: poc, load: @loads).github_advisory_link == nil
  end

  test "sends the case and the written description as the caller, then records the advisory", %{
    poc: poc,
    case: case_record
  } do
    stub_report()

    {:ok, reported} = report(case_record, poc, load: @loads)

    assert_received {:github, "POST", @report_path, ["Bearer gho_token"], body}
    refute_received {:github, "POST", @draft_path, _auth, _body}

    assert body["summary"] == "Header injection in acme_lib"
    assert body["description"] == "Written for the maintainers."
    assert body["cwe_ids"] == ["CWE-113"]
    assert body["credits"] == []
    assert body["vulnerabilities"] == []
    refute Map.has_key?(body, "cvss_vector_string")
    refute Map.has_key?(body, "cve_id")

    assert %{ghsa_id: "GHSA-2cfg-hjmp-qrvw", state: :draft} = reported.github_advisory_link
    assert reported.references == []

    assert [%{url: @hex_url, tags: ["vendor-advisory", "related"]} | _rest] =
             reported.derived_references

    assert reported.__metadata__.github_report == :report
    assert reported.version == case_record.version
  end

  test "reports the case as it stands, not as the caller last loaded it", %{
    poc: poc,
    case: case_record
  } do
    Cases.edit_case!(case_record, %{title: "Header injection in acme_lib, revised"}, actor: poc)
    stub_report()

    assert {:ok, _reported} = report(case_record, poc)

    assert_received {:github, "POST", _path, _auth, %{"summary" => "Header injection in acme_lib, revised"}}
  end

  test "an administrator of the repository opens a draft advisory instead", %{
    poc: poc,
    case: case_record
  } do
    stub_report(true)

    {:ok, reported} = report(case_record, poc, load: @loads)

    assert_received {:github, "POST", @draft_path, ["Bearer gho_token"], draft}
    refute_received {:github, "POST", @report_path, _auth, _body}
    assert draft["summary"] == "Header injection in acme_lib"
    assert draft["description"] == "Written for the maintainers."
    assert %{ghsa_id: "GHSA-2cfg-hjmp-qrvw"} = reported.github_advisory_link
    assert reported.__metadata__.github_report == :draft
  end

  test "the draft carries the assigned CVE ID", %{poc: poc, case: case_record} do
    record = Fixtures.reserved_cve_record("CVE-2026-48858")
    assigned = Cases.assign_case_cve_id!(case_record, %{cve_record_id: record.id}, actor: poc)
    stub_report(true)

    assert {:ok, _reported} = report(assigned, poc)

    assert_received {:github, "POST", @draft_path, _auth, %{"cve_id" => "CVE-2026-48858"}}
  end

  test "a refusal from GitHub reports nothing and links nothing", %{poc: poc, case: case_record} do
    stub_refusal(false, 403, %{"message" => "Private vulnerability reporting is disabled"})

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, poc)

    assert message == "was refused by GitHub: Private vulnerability reporting is disabled"
    assert_unlinked(case_record, poc)
  end

  test "a refusal of an administrator's draft reports nothing and links nothing", %{
    poc: poc,
    case: case_record
  } do
    stub_refusal(true, 403, %{"message" => "Resource not accessible by integration"})

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, poc)

    assert_received {:github, "POST", @draft_path, _auth, _body}
    assert message == "was refused by GitHub: Resource not accessible by integration"
    assert_unlinked(case_record, poc)
  end

  test "a repository GitHub does not show the caller takes no report", %{
    poc: poc,
    case: case_record
  } do
    GitHubApi.stub(fn conn ->
      assert conn.method == "GET"
      assert conn.path_info == @repository_path
      conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"message" => "Not Found"})
    end)

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, poc)

    assert message == "is not a repository you can report to on GitHub"
    assert_unlinked(case_record, poc)
  end

  test "a repository the administrator cannot open an advisory on takes no draft", %{
    poc: poc,
    case: case_record
  } do
    stub_refusal(true, 404, %{"message" => "Not Found"})

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, poc)

    assert message == "is not a repository where you can open an advisory on GitHub"
    assert_unlinked(case_record, poc)
  end

  test "a token GitHub no longer accepts sends nothing", %{poc: poc, case: case_record} do
    GitHubApi.stub(fn conn ->
      assert conn.path_info == @repository_path
      conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
    end)

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, poc)

    assert message == "needs you to sign in with GitHub again"
    assert_unlinked(case_record, poc)
  end

  test "needs the caller's GitHub account, before GitHub is asked", %{case: case_record} do
    stub_github_unreachable()
    hex_poc = Fixtures.sign_in_with_hex("report_hex", "report_hex")
    hex_poc = Ash.update!(hex_poc, %{role: :poc}, action: :set_role, authorize?: false)

    assert {:error, %Invalid{errors: [%{field: :repo, message: message}]}} =
             report(case_record, hex_poc)

    assert message == "needs your GitHub account linked"
  end

  test "a linked case is refused before GitHub is asked", %{poc: poc, case: case_record} do
    assert Cases.can_report_case_to_github?(poc, case_record, @report)

    GitHubApi.stub_advisory(hex_advisory())
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @hex_url}, actor: poc)
    stub_github_unreachable()

    refute Cases.can_report_case_to_github?(poc, case_record, @report)
    assert {:error, %Forbidden{}} = report(case_record, poc)
  end

  test "a frozen case is refused before GitHub is asked", %{poc: poc, case: case_record} do
    approved =
      case_record |> Cases.request_case_review!(actor: poc) |> Cases.approve_case!(actor: poc)

    stub_github_unreachable()

    refute Cases.can_report_case_to_github?(poc, approved, @report)
    assert {:error, %Forbidden{}} = report(approved, poc)
    assert_unlinked(case_record, poc)
  end

  test "an assigned supporter reports", %{poc: poc, case: case_record} do
    supporter = Fixtures.register_user("report_supporter", :supporter)
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
    stub_report()

    assert {:ok, reported} = report(case_record, supporter, load: @loads)
    assert_received {:github, "POST", _path, ["Bearer gho_token"], _body}
    assert %{ghsa_id: "GHSA-2cfg-hjmp-qrvw"} = reported.github_advisory_link
  end

  test "nobody else reports, and is refused before GitHub is asked", %{
    poc: poc,
    case: case_record
  } do
    collaborator = Fixtures.register_user("report_collaborator")
    Cases.assign_case_user!(%{case_id: case_record.id, user_id: collaborator.id}, actor: poc)
    nobody = Fixtures.register_user("report_nobody")
    stranger = Fixtures.register_user("report_stranger", :supporter)
    stub_github_unreachable()

    for actor <- [nil, collaborator, nobody, stranger] do
      assert {:error, %Forbidden{}} = report(case_record, actor)
    end

    assert_unlinked(case_record, poc)
  end
end
