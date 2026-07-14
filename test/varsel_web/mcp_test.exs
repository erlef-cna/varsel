# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.McpTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias Varsel.CVE.CveRecord

  @year Date.utc_today().year

  defp mcp(conn, method, params \\ %{}) do
    conn
    |> put_req_header("content-type", "application/json")
    |> put_req_header("accept", "application/json")
    |> post("/mcp", Jason.encode!(%{jsonrpc: "2.0", id: 1, method: method, params: params}))
  end

  test "anonymous tools/list shows the public tools but hides lifecycle tools", %{conn: conn} do
    body = response(mcp(conn, "tools/list"), 200)

    for tool <- ~w(list_cves get_cve search_cves validate_cve_record list_weaknesses
                   list_attack_patterns list_osv_records) do
      assert body =~ tool
    end

    refute body =~ "assign_cve"
    refute body =~ "set_user_role"
  end

  test "a POC's tools/list includes the lifecycle and user tools", %{conn: conn} do
    poc = register_user("poc", :poc)
    {_api_key, plaintext} = create_api_key(poc)

    body =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> mcp("tools/list")
      |> response(200)

    for tool <- ~w(list_all_cves available_cve_ids assign_cve update_cve
                   request_publish_cve reject_cve list_users update_user set_user_role) do
      assert body =~ tool
    end
  end

  test "public tools work without authentication", %{conn: conn} do
    published_cve_record("CVE-#{@year}-4001", "Published thing")

    body =
      response(
        mcp(conn, "tools/call", %{name: "list_cves", arguments: %{}}),
        200
      )

    assert body =~ "CVE-#{@year}-4001"
  end

  test "lifecycle tools are rejected without authentication", %{conn: conn} do
    record = reserved_cve_record("CVE-#{@year}-4002")

    mcp(conn, "tools/call", %{name: "assign_cve", arguments: %{id: record.id}})

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
end
