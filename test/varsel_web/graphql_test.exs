# SPDX-FileCopyrightText: 2026 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GraphqlTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Fixtures

  alias AshAuthentication.Oauth2Server.Jwt
  alias AshAuthentication.Plug.Helpers, as: AuthPlug
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

  describe "anonymous requests" do
    test "are rejected with the OAuth discovery challenge", %{conn: conn} do
      conn = post(conn, "/gql", %{"query" => "{ listPublishedCves { cveId } }"})

      assert response(conn, 401)
      assert [challenge] = get_resp_header(conn, "www-authenticate")
      assert challenge =~ "resource_metadata"
    end

    test "cannot execute mutations", %{conn: conn} do
      record = reserved_cve_record("CVE-#{@year}-3002")

      conn =
        post(conn, "/gql", %{
          "query" => "mutation($id: ID!) { assignCve(id: $id) { result { id } }}",
          "variables" => %{"id" => record.id}
        })

      assert response(conn, 401)
      assert Ash.get!(CveRecord, record.id, authorize?: false).state == :reserved
    end
  end

  describe "API-key authenticated POC" do
    test "listPublishedCves returns published records only", %{conn: conn} do
      poc = register_user("poc", :poc)
      published_cve_record("CVE-#{@year}-3001", "Published thing")

      body =
        conn
        |> with_api_key(poc)
        |> gql("{ listPublishedCves { cveId title } }")

      assert body["data"]["listPublishedCves"] == [
               %{"cveId" => "CVE-#{@year}-3001", "title" => "Published thing"}
             ]
    end

    test "validateCveSchema validates the Json scalar input", %{conn: conn} do
      poc = register_user("poc", :poc)

      body =
        conn
        |> with_api_key(poc)
        |> gql(
          "query($json: Json!) { validateCveSchema(cveJson: $json) { valid errors { message } } }",
          %{"json" => "{}"}
        )

      result = body["data"]["validateCveSchema"]
      assert result["valid"] == false
      assert result["errors"] != []
    end

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

    test "an invalid bearer token is rejected", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer not-a-valid-token")
        |> post("/gql", %{"query" => "{ listPublishedCves { cveId } }"})

      assert response(conn, 401)
    end
  end

  describe "playground" do
    defp log_in(conn, user) do
      conn
      |> init_test_session(%{})
      |> AuthPlug.store_in_session(user)
    end

    test "anonymous visitors are redirected to sign in", %{conn: conn} do
      conn = get(conn, "/gql/playground")
      assert redirected_to(conn) == "/sign-in"
    end

    test "renders for a logged-in user", %{conn: conn} do
      user = register_user("alice")

      conn =
        conn
        |> log_in(user)
        |> put_req_header("accept", "text/html")
        |> get("/gql/playground")

      assert html_response(conn, 200) =~ ~r/graphiql/i
    end

    test "executes queries with the session actor", %{conn: conn} do
      user = register_user("alice")
      published_cve_record("CVE-#{@year}-3001", "Published thing")

      body =
        conn
        |> log_in(user)
        |> put_req_header("accept", "application/json")
        |> post("/gql/playground", %{"query" => "{ listPublishedCves { cveId } }"})
        |> json_response(200)

      assert body["data"]["listPublishedCves"] == [%{"cveId" => "CVE-#{@year}-3001"}]
    end
  end
end
