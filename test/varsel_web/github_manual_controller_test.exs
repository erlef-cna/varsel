# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.GitHubManualControllerTest do
  use VarselWeb.ConnCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias AshAuthentication.Jwt
  alias AshAuthentication.TokenResource
  alias Varsel.Accounts.Token
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.Fixtures
  alias Varsel.Test.GitHubApi

  require Ash.Query

  @ghsa_id "GHSA-4v2x-7mq8-w3rf"
  @url "https://github.com/acme/other_lib/security/advisories/#{@ghsa_id}"

  defp answer(overrides \\ %{}) do
    hex_advisory()
    |> Map.merge(%{"ghsa_id" => @ghsa_id, "html_url" => @url})
    |> Map.merge(overrides)
  end

  defp seed_link!(case_record) do
    Ash.Seed.seed!(GitHubAdvisoryLink, %{
      case_id: case_record.id,
      ghsa_id: @ghsa_id,
      owner: "acme",
      repo: "other_lib",
      html_url: @url,
      state: :draft,
      title: "Header injection in acme_lib",
      advisory: answer(),
      fetched_at: DateTime.truncate(DateTime.utc_now(), :second)
    })
  end

  defp fetch(conn, request, token) do
    conn
    |> put_req_header("authorization", "Bearer #{token}")
    |> get(~p"/api/github/manual/#{request.id}/request")
  end

  defp post_result(conn, request, token, body) do
    conn
    |> put_req_header("authorization", "Bearer #{token}")
    |> put_req_header("content-type", "application/json")
    |> post(~p"/api/github/manual/#{request.id}/result", JSON.encode!(body))
  end

  defp link_of(case_record, poc) do
    Cases.list_github_advisory_links!(
      actor: poc,
      query: [filter: [case_id: case_record.id]],
      load: []
    )
  end

  setup %{conn: conn} do
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked") end)
    poc = Fixtures.register_user("manual_api_poc#{System.unique_integer([:positive])}", :poc)

    %{
      conn: conn,
      poc: poc,
      case: Fixtures.open_case(poc, %{title: "Header injection in other_lib"})
    }
  end

  describe "the request" do
    setup %{poc: poc, case: case_record} do
      link = seed_link!(case_record)
      Cases.edit_case!(case_record, %{title: "Header injection, revised"}, actor: poc)
      request = Cases.prepare_manual_push!(link.id, [:title], actor: poc)
      %{request: request, token: request.__metadata__.token}
    end

    test "answers the body to send and stamps the fetch", %{
      conn: conn,
      poc: poc,
      request: request,
      token: token
    } do
      assert %{"summary" => "Header injection, revised"} =
               conn |> fetch(request, token) |> json_response(200)

      assert %DateTime{} = Cases.get_github_manual_request!(request.id, actor: poc).fetched_at
    end

    test "refuses a wrong, expired or revoked token and an unknown id", %{
      conn: conn,
      poc: poc,
      request: request,
      token: token
    } do
      assert %{"ok" => false} = conn |> fetch(request, "wrong") |> json_response(401)

      assert %{"ok" => false} =
               conn |> fetch(%{id: Ash.UUID.generate()}, token) |> json_response(404)

      assert %{"ok" => false} = conn |> fetch(%{id: "not-an-id"}, token) |> json_response(404)

      assert %{"ok" => false} =
               build_conn()
               |> get(~p"/api/github/manual/#{request.id}/request")
               |> json_response(401)

      past = DateTime.utc_now() |> DateTime.shift(minute: -1) |> DateTime.to_unix()

      {:ok, expired, _claims} =
        Jwt.token_for_user(poc, %{"request_id" => request.id, "exp" => past}, purpose: :github_manual)

      assert %{"ok" => false} = conn |> fetch(request, expired) |> json_response(401)

      :ok = TokenResource.revoke(Token, token, store_all_tokens?: true)

      assert %{"ok" => false} = build_conn() |> fetch(request, token) |> json_response(401)
    end

    test "refuses a request that is done, whose token is revoked", %{
      conn: conn,
      request: request,
      token: token
    } do
      assert %{"ok" => true} = conn |> post_result(request, token, answer()) |> json_response(200)
      assert %{"ok" => false} = build_conn() |> fetch(request, token) |> json_response(401)
    end
  end

  describe "the result" do
    test "of a link read links the advisory as the POC", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)

      assert %{"ok" => true, "message" => "Linked GHSA-4v2x-7mq8-w3rf to the case."} =
               conn
               |> post_result(request, request.__metadata__.token, answer())
               |> json_response(200)

      assert [%{ghsa_id: @ghsa_id, repo: "other_lib"}] = link_of(case_record, poc)

      assert [%{user_id: user_id}] =
               GitHubAdvisoryLink.Version
               |> Ash.Query.filter(version_action_name == :link_attested)
               |> Ash.read!(authorize?: false)

      assert user_id == poc.id
    end

    test "of a refresh stores the advisory again", %{conn: conn, poc: poc, case: case_record} do
      link = seed_link!(case_record)
      request = Cases.prepare_manual_refresh!(link.id, actor: poc)

      assert %{"ok" => true} =
               conn
               |> post_result(
                 request,
                 request.__metadata__.token,
                 answer(%{"summary" => "Revised on GitHub"})
               )
               |> json_response(200)

      assert [%{title: "Revised on GitHub"}] = link_of(case_record, poc)
    end

    test "of a pull stores the advisory and pulls the fields onto the case", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      link = seed_link!(case_record)
      request = Cases.prepare_manual_pull!(link.id, [:title], actor: poc)

      assert %{"ok" => true, "message" => "Read GHSA-4v2x-7mq8-w3rf again and pulled Title."} =
               conn
               |> post_result(
                 request,
                 request.__metadata__.token,
                 answer(%{"summary" => "Pulled title"})
               )
               |> json_response(200)

      assert %{title: "Pulled title"} = Cases.get_case!(case_record.id, actor: poc)
    end

    test "of a push stores the advisory GitHub answered", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      link = seed_link!(case_record)
      Cases.edit_case!(case_record, %{title: "Header injection, revised"}, actor: poc)
      request = Cases.prepare_manual_push!(link.id, [:title], actor: poc)

      assert %{"ok" => true} =
               conn
               |> post_result(
                 request,
                 request.__metadata__.token,
                 answer(%{"summary" => "Header injection, revised"})
               )
               |> json_response(200)

      assert [%{title: "Header injection, revised"}] = link_of(case_record, poc)
    end

    test "of a report links the advisory GitHub opened", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      request =
        Cases.prepare_manual_report!(case_record.id, "acme", "other_lib", "For you.", actor: poc)

      assert %{
               "ok" => true,
               "message" => "Opened the draft advisory GHSA-4v2x-7mq8-w3rf. It is linked to the case."
             } =
               conn
               |> post_result(request, request.__metadata__.token, answer())
               |> json_response(200)

      assert [%{ghsa_id: @ghsa_id}] = link_of(case_record, poc)
    end

    test "refuses an advisory of another repository or another advisory", %{
      conn: conn,
      poc: poc,
      case: case_record
    } do
      link = seed_link!(case_record)
      request = Cases.prepare_manual_refresh!(link.id, actor: poc)
      token = request.__metadata__.token

      other_repo =
        answer(%{
          "html_url" => "https://github.com/acme/acme_lib/security/advisories/#{@ghsa_id}"
        })

      assert %{
               "ok" => false,
               "message" => "GitHub's answer is an advisory of acme/acme_lib, not of acme/other_lib."
             } =
               conn |> post_result(request, token, other_repo) |> json_response(422)

      other_ghsa =
        answer(%{
          "ghsa_id" => "GHSA-2cfg-hjmp-qrvw",
          "html_url" => "https://github.com/acme/other_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
        })

      assert %{
               "ok" => false,
               "message" => "GitHub's answer is GHSA-2cfg-hjmp-qrvw, not GHSA-4v2x-7mq8-w3rf."
             } =
               build_conn() |> post_result(request, token, other_ghsa) |> json_response(422)

      assert %{
               "ok" => false,
               "message" => "GitHub's answer is not an advisory. GitHub answered: Not Found."
             } =
               build_conn()
               |> post_result(request, token, %{"message" => "Not Found"})
               |> json_response(422)

      assert [%{title: "Header injection in acme_lib"}] = link_of(case_record, poc)
    end

    test "is taken once", %{conn: conn, poc: poc, case: case_record} do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)
      token = request.__metadata__.token

      assert %{"ok" => true} = conn |> post_result(request, token, answer()) |> json_response(200)

      assert %{"ok" => false} =
               build_conn() |> post_result(request, token, answer()) |> json_response(401)

      assert %{purpose: "revocation"} = Ash.get!(Token, request.token_id, authorize?: false)
    end

    test "is JSON", %{conn: conn, poc: poc, case: case_record} do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)
      token = request.__metadata__.token

      assert %{"ok" => false} =
               conn
               |> put_req_header("authorization", "Bearer #{token}")
               |> put_req_header("content-type", "text/plain")
               |> post(~p"/api/github/manual/#{request.id}/result", JSON.encode!(answer()))
               |> json_response(415)

      assert %{"ok" => false} =
               build_conn()
               |> put_req_header("authorization", "Bearer #{token}")
               |> post(~p"/api/github/manual/#{request.id}/result")
               |> json_response(415)

      assert [] = link_of(case_record, poc)
    end
  end
end
