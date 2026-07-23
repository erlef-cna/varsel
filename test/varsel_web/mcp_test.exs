# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.McpTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Oauth2Server.Jwt
  alias Varsel.CVE.CveRecord

  @year Date.utc_today().year

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

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/list")
      |> response(200)

    for tool <- ~w(list_all_cves available_cve_ids assign_cve update_cve
                   request_publish_cve reject_cve list_users update_user set_user_role
                   submit_vulnerability_report list_cases get_case render_case_preview
                   refresh_case_derivation list_case_proposals list_open_case_proposals
                   propose_title propose_credit propose_weakness propose_reference
                   propose_otp_affected_package propose_version_event propose_delete
                   withdraw_case_proposal list_case_comments
                   create_case_comment) do
      assert body =~ tool
    end
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

  test "lifecycle tools work with an OAuth access token", %{conn: conn} do
    poc = register_user("poc", :poc)
    record = reserved_cve_record("CVE-#{@year}-4003")

    conn
    |> put_req_header("authorization", "Bearer " <> mint_access_token(poc))
    |> mcp("tools/call", %{name: "assign_cve", arguments: %{id: record.id}})

    assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
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
