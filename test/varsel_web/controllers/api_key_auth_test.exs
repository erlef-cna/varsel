# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ApiKeyAuthTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  @query %{"query" => "{ listPublishedCves { cveId } }"}

  test "requests without a key are rejected", %{conn: conn} do
    conn = post(conn, "/gql", @query)
    assert conn.status == 401
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

  # Non-API-key bearer tokens fall through this plug to OauthBearerAuth,
  # which hard-401s anything it can't resolve instead of downgrading the
  # request to anonymous.
  test "non-API-key bearer tokens fall through to OAuth validation", %{conn: conn} do
    conn =
      conn
      |> put_req_header("authorization", "Bearer not-an-api-key")
      |> post("/gql", @query)

    assert conn.status == 401
  end
end
