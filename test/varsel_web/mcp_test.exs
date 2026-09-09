# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.McpTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures
  import Varsel.Test.GitHubAdvisoryFixtures

  alias AshAuthentication.Oauth2Server.Jwt
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.CVE.CveRecord
  alias Varsel.Test.GitHubApi

  @year Date.utc_today().year
  @hex_url "https://github.com/acme/acme_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
  @advisory_tools ~w(open_case_from_github_advisory get_case_github_advisory
                     link_github_advisory unlink_github_advisory
                     refresh_github_advisory_link pull_github_advisory)

  defp mcp(conn, method, params \\ %{}) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("accept", "application/json")
    |> post("/mcp", Jason.encode!(%{jsonrpc: "2.0", id: 1, method: method, params: params}))
  end

  defp mint_access_token(user, scope \\ "mcp") do
    {:ok, token, _claims} =
      Jwt.mint(Varsel.Oauth2Server, sub: user.id, client_id: "test-client", scope: scope)

    token
  end

  test "anonymous requests are rejected with the OAuth discovery challenge", %{conn: conn} do
    conn = mcp(conn, "tools/list")

    assert response(conn, 401)

    assert [challenge] = get_resp_header(conn, "www-authenticate")

    assert challenge =~
             ~s|resource_metadata="http://localhost:4002/.well-known/oauth-protected-resource"|
  end

  test "an invalid bearer token is rejected", %{conn: conn} do
    conn =
      conn
      |> put_req_header("authorization", "Bearer not-a-valid-token")
      |> mcp("tools/list")

    assert response(conn, 401)
  end

  test "a supporter's tools/list shows the public tools but hides lifecycle tools", %{conn: conn} do
    supporter = register_user("supporter", :supporter)
    {_api_key, plaintext} = create_api_key(supporter)

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/list")
      |> response(200)

    for tool <- ~w(list_cves get_cve search_cves validate_cve_record list_weaknesses
                   list_attack_patterns list_osv_records) do
      assert body =~ tool
    end

    refute body =~ "assign_cve"
    refute body =~ "set_user_role"
  end

  # Presence in tools/list doubles as a regression test for the empty-input
  # permission probe: when an action's validation crashes on it, AshAi
  # swallows the error and silently hides the tool.
  test "a POC's tools/list includes every registered tool", %{conn: conn} do
    poc = register_user("poc", :poc)
    {_api_key, plaintext} = create_api_key(poc)

    names = tool_names(conn, plaintext)

    for tool <- ~w(list_all_cves available_cve_ids assign_cve update_cve validate_cve
                   request_publish_cve reject_cve list_users update_user set_user_role
                   submit_vulnerability_report list_cases get_case render_case_preview
                   validate_case
                   refresh_case_derivation list_case_proposals list_open_case_proposals
                   propose_title propose_credit propose_weakness propose_reference
                   propose_internal_notes propose_technical_analysis propose_proof_of_concept
                   propose_impact propose_impact_description
                   propose_otp_affected_package propose_version_event propose_delete
                   withdraw_case_proposal list_case_comments
                   grant_case_access) ++ @advisory_tools do
      assert tool in names
    end
  end

  # The link's policy decides on the case a changeset names. The probe names
  # none, and the tool has to stay listed for the roles that may link.
  test "a supporter's tools/list carries the advisory tools", %{conn: conn} do
    supporter = register_user("supporter", :supporter)
    {_api_key, plaintext} = create_api_key(supporter)

    names = tool_names(conn, plaintext)

    for tool <- @advisory_tools do
      assert tool in names
    end
  end

  test "a role-less user's tools/list carries no advisory write", %{conn: conn} do
    register_user("bootstrap_poc")
    nobody = register_user("nobody")
    {_api_key, plaintext} = create_api_key(nobody)

    names = tool_names(conn, plaintext)

    for tool <- ~w(open_case_from_github_advisory link_github_advisory
                   unlink_github_advisory pull_github_advisory) do
      refute tool in names
    end
  end

  describe "the advisory tools" do
    setup do
      GitHubApi.stub_advisory(hex_advisory())
      poc = register_user("poc", :poc)
      {_api_key, plaintext} = create_api_key(poc)

      %{poc: poc, plaintext: plaintext}
    end

    test "open_case_from_github_advisory opens a linked case", %{
      conn: conn,
      poc: poc,
      plaintext: plaintext
    } do
      row =
        conn
        |> tool_call(plaintext, "open_case_from_github_advisory", %{
          input: %{advisory_url: @hex_url}
        })
        |> tool_result()

      assert %{"id" => id, "title" => "Header injection in acme_lib", "state" => "draft"} = row

      case_record = Cases.get_case!(id, actor: poc, load: [github_advisory_link: [:ghsa_id]])
      assert case_record.github_advisory_link.ghsa_id == "GHSA-2cfg-hjmp-qrvw"
    end

    test "get_case_github_advisory answers the link and the diff rows", %{
      conn: conn,
      poc: poc,
      plaintext: plaintext
    } do
      case_record = open_case(poc, %{title: "Working title"})
      link_advisory!(case_record, poc)

      row =
        conn
        |> tool_call(plaintext, "get_case_github_advisory", %{case_id: case_record.id})
        |> tool_result()

      assert %{"case_id" => case_id, "ghsa_id" => "GHSA-2cfg-hjmp-qrvw", "diff" => rows} = row
      assert case_id == case_record.id
      refute Map.has_key?(row, "advisory")

      assert %{
               "field" => "title",
               "ours" => "Working title",
               "theirs" => "Header injection in acme_lib",
               "status" => "differs"
             } = Enum.find(rows, &(&1["field"] == "title"))

      assert %{"field" => "affected", "package" => "erlang/acme_lib", "status" => "theirs_only"} =
               Enum.find(rows, &(&1["field"] == "affected"))
    end

    test "get_case_github_advisory finds nothing for an unlinked case", %{
      conn: conn,
      poc: poc,
      plaintext: plaintext
    } do
      case_record = open_case(poc)

      assert %{"isError" => true} =
               conn
               |> tool_call(plaintext, "get_case_github_advisory", %{case_id: case_record.id})
               |> Map.fetch!("result")
    end

    test "pull_github_advisory takes the fields onto the case", %{
      conn: conn,
      poc: poc,
      plaintext: plaintext
    } do
      case_record = open_case(poc, %{title: "Working title"})
      link_advisory!(case_record, poc)

      row =
        conn
        |> tool_call(plaintext, "pull_github_advisory", %{
          case_id: case_record.id,
          input: %{fields: ["title"]}
        })
        |> tool_result()

      assert %{"field" => "title", "status" => "same"} =
               Enum.find(row["diff"], &(&1["field"] == "title"))

      assert Cases.get_case!(case_record.id, actor: poc).title == "Header injection in acme_lib"
    end

    test "link_github_advisory is refused for a supporter off the case", %{
      conn: conn,
      poc: poc
    } do
      case_record = open_case(poc)
      supporter = register_user("supporter", :supporter)
      {_api_key, plaintext} = create_api_key(supporter)
      GitHubApi.stub(fn _conn -> flunk("GitHub was contacted before the caller was refused") end)

      assert %{"isError" => true, "content" => [%{"text" => text}]} =
               conn
               |> tool_call(plaintext, "link_github_advisory", %{
                 input: %{case_id: case_record.id, advisory_url: @hex_url}
               })
               |> Map.fetch!("result")

      assert text =~ "forbidden"
      assert Ash.read!(GitHubAdvisoryLink, authorize?: false) == []
    end
  end

  defp tool_names(conn, plaintext) do
    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/list")
      |> json_response(200)

    Enum.map(body["result"]["tools"], & &1["name"])
  end

  defp tool_call(conn, plaintext, name, arguments) do
    conn
    |> put_req_header("authorization", "Bearer " <> plaintext)
    |> mcp("tools/call", %{name: name, arguments: arguments})
    |> json_response(200)
  end

  defp tool_result(body) do
    assert %{"result" => %{"content" => [%{"text" => text}]} = result} = body
    refute result["isError"], text

    Jason.decode!(text)
  end

  defp link_advisory!(case_record, actor) do
    Cases.link_github_advisory!(%{case_id: case_record.id, advisory_url: @hex_url}, actor: actor)
  end

  test "public tools work with an API key", %{conn: conn} do
    supporter = register_user("supporter", :supporter)
    {_api_key, plaintext} = create_api_key(supporter)
    published_cve_record("CVE-#{@year}-4001", "Published thing")

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/call", %{name: "list_cves", arguments: %{}})
      |> response(200)

    assert body =~ "CVE-#{@year}-4001"
  end

  test "lifecycle tools are rejected without authentication", %{conn: conn} do
    record = reserved_cve_record("CVE-#{@year}-4002")

    conn = mcp(conn, "tools/call", %{name: "assign_cve", arguments: %{id: record.id}})

    assert response(conn, 401)
    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :reserved
  end

  test "lifecycle tools work with a POC API key", %{conn: conn} do
    poc = register_user("poc", :poc)
    {_api_key, plaintext} = create_api_key(poc)
    record = reserved_cve_record("CVE-#{@year}-4002")

    conn
    |> put_req_header("authorization", "Bearer " <> plaintext)
    |> mcp("tools/call", %{name: "assign_cve", arguments: %{id: record.id}})

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
  end

  test "grant_case_access replies with the case's membership, not its body", %{conn: conn} do
    GitHubApi.stub(fn conn ->
      Req.Test.json(conn, %{"login" => "octocat", "email" => "octocat@example.com"})
    end)

    poc = register_user("poc", :poc)
    {_api_key, plaintext} = create_api_key(poc)
    case_record = open_case(poc)

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/call", %{
        name: "grant_case_access",
        arguments: %{id: case_record.id, input: %{strategy: "github", username: "octocat"}}
      })
      |> json_response(200)

    assert %{"result" => %{"content" => [%{"text" => text}]}} = body
    row = Jason.decode!(text)

    assert Enum.sort(Map.keys(row)) == ~w(assignments id invites)
    assert [%{"username" => "octocat"}] = row["invites"]
  end

  test "lifecycle tools work with an OAuth access token", %{conn: conn} do
    poc = register_user("poc", :poc)
    record = reserved_cve_record("CVE-#{@year}-4003")

    conn
    |> put_req_header("authorization", "Bearer " <> mint_access_token(poc))
    |> mcp("tools/call", %{name: "assign_cve", arguments: %{id: record.id}})

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
  end

  test "submit_vulnerability_report is rate limited for users without a role", %{conn: conn} do
    # The first-ever user auto-becomes POC; the reporter must stay unroled.
    register_user("bootstrap_poc")
    reporter = register_user("reporter")
    {_api_key, plaintext} = create_api_key(reporter)

    Varsel.Hammer.hit(
      "vulnerability_report:submit:user:#{reporter.id}",
      to_timeout(day: 1),
      25,
      25
    )

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/call", %{
        name: "submit_vulnerability_report",
        arguments: %{
          input: %{
            report_json: %{"x" => 1},
            summary: "a bug",
            confirms_criteria: true,
            confirms_in_scope: true
          }
        }
      })
      |> json_response(200)

    assert %{"result" => %{"isError" => true, "content" => [%{"text" => text}]}} = body
    assert text =~ "Rate limit exceeded"

    assert Ash.read!(Varsel.CVE.VulnerabilityReport, authorize?: false) == []
  end

  test "a token without the mcp scope is rejected with insufficient_scope", %{conn: conn} do
    poc = register_user("poc", :poc)

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> mint_access_token(poc, "gql"))
      |> mcp("tools/list")

    assert response(conn, 403)
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s|error="insufficient_scope"|
    assert challenge =~ ~s|scope="mcp"|
  end
end
