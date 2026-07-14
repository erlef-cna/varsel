# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.ApiKeyAuthTest do
  use CveManagementWeb.ConnCase, async: false

  import CveManagement.Fixtures

  @query %{"query" => "{ listPublishedCves { cveId } }"}

  test "public queries work without a key", %{conn: conn} do
    conn = post(conn, "/gql", @query)
    assert %{"data" => _data} = json_response(conn, 200)
  end

  test "a present-but-invalid API key is a hard 401", %{conn: conn} do
    conn =
      conn
      |> put_req_header("authorization", "Bearer eefcna_invalid")
      |> post("/gql", @query)

    assert conn.status == 401
  end

  test "a valid API key authenticates the request", %{conn: conn} do
    user = register_user("alice", :poc)
    {_api_key, plaintext} = create_api_key(user)

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> plaintext)
      |> post("/gql", @query)

    assert %{"data" => _data} = json_response(conn, 200)
    assert conn.assigns.current_user.id == user.id
  end

  test "non-API-key bearer tokens fall through untouched", %{conn: conn} do
    conn =
      conn
      |> put_req_header("authorization", "Bearer not-an-api-key")
      |> post("/gql", @query)

    assert %{"data" => _data} = json_response(conn, 200)
  end
end
