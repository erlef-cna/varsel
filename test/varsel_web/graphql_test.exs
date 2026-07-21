# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Oauth2Server.Jwt
  alias Varsel.CVE.CveRecord

  @year Date.utc_today().year

  defp gql(conn, query, variables \\ %{}) do
    conn
    |> post("/gql", %{"query" => query, "variables" => variables})
    |> json_response(200)
  end

  defp with_api_key(conn, user) do
    {_api_key, plaintext} = create_api_key(user)
    put_req_header(conn, "authorization", "Bearer " <> plaintext)
  end

  defp with_oauth_token(conn, user, scope \\ "gql") do
    {:ok, token, _claims} =
      Jwt.mint(Varsel.Oauth2Server, sub: user.id, client_id: "test-client", scope: scope)

    put_req_header(conn, "authorization", "Bearer " <> token)
  end

  describe "anonymous queries" do
    test "listPublishedCves returns published records only", %{conn: conn} do
      published_cve_record("CVE-#{@year}-3001", "Published thing")
      reserved_cve_record("CVE-#{@year}-3002")

      body = gql(conn, "{ listPublishedCves { cveId title } }")

      assert body["data"]["listPublishedCves"] == [
               %{"cveId" => "CVE-#{@year}-3001", "title" => "Published thing"}
             ]
    end

    test "getPublishedCve looks up by cveId argument", %{conn: conn} do
      published_cve_record("CVE-#{@year}-3001", "Published thing")

      body =
        gql(conn, "query($cveId: String!) { getPublishedCve(cveId: $cveId) { title } }", %{
          "cveId" => "CVE-#{@year}-3001"
        })

      assert body["data"]["getPublishedCve"]["title"] == "Published thing"
    end

    test "validateCveSchema runs without authentication", %{conn: conn} do
      # The Json scalar takes JSON-encoded strings as input.
      body =
        gql(
          conn,
          "query($json: Json!) { validateCveSchema(cveJson: $json) { valid errors { message } } }",
          %{
            "json" => "{}"
          }
        )

      result = body["data"]["validateCveSchema"]
      assert result["valid"] == false
      assert result["errors"] != []
    end

    test "assignCve is rejected without an actor", %{conn: conn} do
      record = reserved_cve_record("CVE-#{@year}-3002")

      body =
        gql(
          conn,
          "mutation($id: ID!) { assignCve(id: $id) { result { id } errors { message } } }",
          %{
            "id" => record.id
          }
        )

      refute get_in(body, ["data", "assignCve", "result", "id"])
      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :reserved
    end
  end

  describe "API-key authenticated POC" do
    test "listAllCves includes unpublished records", %{conn: conn} do
      poc = register_user("poc", :poc)
      reserved_cve_record("CVE-#{@year}-3002")

      body =
        conn
        |> with_api_key(poc)
        |> gql("{ listAllCves { cveId state } }")

      assert [%{"state" => "reserved"}] = body["data"]["listAllCves"]
    end

    test "assignCve transitions reserved to draft", %{conn: conn} do
      poc = register_user("poc", :poc)
      record = reserved_cve_record("CVE-#{@year}-3002")

      body =
        conn
        |> with_api_key(poc)
        |> gql(
          "mutation($id: ID!) { assignCve(id: $id) { result { state } errors { message } } }",
          %{
            "id" => record.id
          }
        )

      assert body["data"]["assignCve"]["errors"] in [nil, []]
      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
    end

    test "setUserRole updates a user's role", %{conn: conn} do
      poc = register_user("poc", :poc)
      alice = register_user("alice")

      body =
        conn
        |> with_api_key(poc)
        |> gql(
          "mutation($id: ID!) { setUserRole(id: $id, input: {role: SUPPORTER}) { result { role } errors { message } } }",
          %{"id" => alice.id}
        )

      assert body["data"]["setUserRole"]["result"]["role"] == "SUPPORTER"
    end
  end

  describe "OAuth-token authenticated POC" do
    test "listAllCves includes unpublished records", %{conn: conn} do
      poc = register_user("poc", :poc)
      reserved_cve_record("CVE-#{@year}-3002")

      body =
        conn
        |> with_oauth_token(poc)
        |> gql("{ listAllCves { cveId state } }")

      assert [%{"state" => "reserved"}] = body["data"]["listAllCves"]
    end

    test "assignCve transitions reserved to draft", %{conn: conn} do
      poc = register_user("poc", :poc)
      record = reserved_cve_record("CVE-#{@year}-3002")

      body =
        conn
        |> with_oauth_token(poc)
        |> gql(
          "mutation($id: ID!) { assignCve(id: $id) { result { state } errors { message } } }",
          %{
            "id" => record.id
          }
        )

      assert body["data"]["assignCve"]["errors"] in [nil, []]
      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :draft
    end

    test "a token without the gql scope is rejected with insufficient_scope", %{conn: conn} do
      poc = register_user("poc", :poc)

      conn =
        conn
        |> with_oauth_token(poc, "mcp")
        |> post("/gql", %{"query" => "{ listAllCves { cveId } }"})

      assert response(conn, 403)
      assert [challenge] = get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s|error="insufficient_scope"|
      assert challenge =~ ~s|scope="gql"|
    end

    test "an invalid bearer token is rejected rather than treated as anonymous", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer not-a-valid-token")
        |> post("/gql", %{"query" => "{ listPublishedCves { cveId } }"})

      assert response(conn, 401)
    end
  end
end
