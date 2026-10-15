# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.GitHubManualRequestTest do
  use Varsel.DataCase, async: false

  import Varsel.Test.GitHubAdvisoryFixtures

  alias Ash.Error.Forbidden
  alias Ash.Error.Invalid
  alias AshAuthentication.Jwt
  alias AshAuthentication.TokenResource
  alias Varsel.Accounts.Token
  alias Varsel.Cases
  alias Varsel.Cases.GitHubAdvisoryLink
  alias Varsel.Fixtures
  alias Varsel.Service
  alias Varsel.Test.GitHubApi

  @ghsa_id "GHSA-4v2x-7mq8-w3rf"
  @url "https://github.com/acme/other_lib/security/advisories/#{@ghsa_id}"

  defp answer(overrides \\ %{}) do
    hex_advisory()
    |> Map.merge(%{"ghsa_id" => @ghsa_id, "html_url" => @url}, fn _key, _old, new ->
      new
    end)
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

  defp service, do: [actor: Service.github_manual()]

  defp locate!(request), do: Cases.locate_github_manual_request!(request.id, service())

  setup do
    GitHubApi.stub(fn _conn -> flunk("GitHub was asked") end)
    poc = Fixtures.register_user("manual_poc#{System.unique_integer([:positive])}", :poc)

    %{poc: poc, case: Fixtures.open_case(poc, %{title: "Header injection in other_lib"})}
  end

  describe "preparing" do
    test "a POC prepares a read that the answer then links, and sees the token once", %{
      poc: poc,
      case: case_record
    } do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)

      assert %{operation: :read, method: :get, owner: "acme", repo: "other_lib", body: nil} =
               request

      assert request.path == "/repos/acme/other_lib/security-advisories/#{@ghsa_id}"
      assert request.advisory_url == @url

      assert {:ok, %{"jti" => jti, "purpose" => "github_manual", "request_id" => request_id}} =
               Jwt.peek(request.__metadata__.token)

      assert request_id == request.id
      assert request.token_id == jti

      stored = Cases.get_github_manual_request!(request.id, actor: poc)
      refute Map.has_key?(stored.__metadata__, :token)

      token_row = Ash.get!(Token, jti, authorize?: false)
      assert token_row.purpose == "github_manual"
      assert token_row.subject == "user?id=#{poc.id}"
      assert DateTime.diff(token_row.expires_at, DateTime.utc_now(), :second) in 890..900
    end

    test "a push carries the body the automatic push would send", %{poc: poc, case: case_record} do
      link = seed_link!(case_record)
      Cases.edit_case!(case_record, %{title: "Header injection, revised"}, actor: poc)

      request = Cases.prepare_manual_push!(link.id, [:title], actor: poc)

      assert %{operation: :push, method: :patch, fields: [:title], ghsa_id: @ghsa_id} = request
      assert request.path == "/repos/acme/other_lib/security-advisories/#{@ghsa_id}"
      assert request.body == %{"summary" => "Header injection, revised"}
    end

    test "a report targets the draft endpoint by default and the report endpoint on request", %{
      poc: poc,
      case: case_record
    } do
      draft =
        Cases.prepare_manual_report!(case_record.id, "acme", "other_lib", "For you.", actor: poc)

      assert draft.path == "/repos/acme/other_lib/security-advisories"

      assert %{"description" => "For you.", "summary" => "Header injection in other_lib"} =
               draft.body

      report =
        Cases.prepare_manual_report!(
          case_record.id,
          "acme",
          "other_lib",
          "For you.",
          %{draft: false},
          actor: poc
        )

      assert report.path == "/repos/acme/other_lib/security-advisories/reports"
      assert %{operation: :report, method: :post} = report
    end

    test "a repository name GitHub would not give is refused", %{poc: poc, case: case_record} do
      assert {:error, %Invalid{}} =
               Cases.prepare_manual_report(case_record.id, "acme", "lib; rm -rf ~", "x", actor: poc)
    end

    test "a supporter prepares nothing, even on a case they work on", %{
      poc: poc,
      case: case_record
    } do
      supporter =
        Fixtures.register_user(
          "manual_supporter#{System.unique_integer([:positive])}",
          :supporter
        )

      Cases.assign_case_user!(%{case_id: case_record.id, user_id: supporter.id}, actor: poc)
      link = seed_link!(case_record)

      assert {:error, %Forbidden{}} = Cases.prepare_manual_refresh(link.id, actor: supporter)

      assert {:error, %Forbidden{}} =
               Cases.prepare_manual_push(link.id, [:title], actor: supporter)
    end

    test "a POC prepares only what they may do on the case", %{poc: poc, case: case_record} do
      Cases.close_case!(case_record, %{}, actor: poc)

      assert {:error, %Forbidden{}} = Cases.prepare_manual_link(case_record.id, @url, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.prepare_manual_report(case_record.id, "acme", "other_lib", "x", actor: poc)
    end

    test "nobody reads another person's request", %{poc: poc, case: case_record} do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)
      other = Fixtures.register_user("manual_other#{System.unique_integer([:positive])}", :poc)

      assert {:error, %Invalid{}} = Cases.get_github_manual_request(request.id, actor: other)
      assert {:error, %Forbidden{}} = Cases.get_github_manual_request(request.id, actor: nil)
      assert {:error, %Forbidden{}} = Cases.locate_github_manual_request(request.id, actor: poc)
    end
  end

  describe "the token" do
    setup %{poc: poc, case: case_record} do
      request = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)
      %{request: request, token: request.__metadata__.token}
    end

    test "fetches the request and stamps the fetch", %{request: request, token: token} do
      fetched = Cases.fetch_github_manual_request!(locate!(request), token, service())
      assert %DateTime{} = fetched.fetched_at
    end

    test "only the request's own token acts", %{request: request} do
      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(locate!(request), "nope", service())

      assert {:error, %Forbidden{}} =
               Cases.complete_github_manual_request(locate!(request), "nope", answer(), service())
    end

    test "an expired or revoked token acts no more", %{poc: poc, request: request, token: token} do
      past = DateTime.utc_now() |> DateTime.shift(minute: -1) |> DateTime.to_unix()

      {:ok, expired, _claims} =
        Jwt.token_for_user(poc, %{"request_id" => request.id, "exp" => past}, purpose: :github_manual)

      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(locate!(request), expired, service())

      :ok = TokenResource.revoke(Token, token, store_all_tokens?: true)

      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(locate!(request), token, service())
    end

    test "a sign-in token of the same POC acts nothing", %{poc: poc, request: request} do
      {:ok, session, _claims} = Jwt.token_for_user(poc, %{"request_id" => request.id})

      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(locate!(request), session, service())
    end

    test "another request's token acts nothing on this one", %{
      poc: poc,
      case: case_record,
      request: request
    } do
      other = Cases.prepare_manual_link!(case_record.id, @url, actor: poc)

      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(
                 locate!(request),
                 other.__metadata__.token,
                 service()
               )
    end

    test "deleting the token row deletes the request", %{poc: poc, request: request} do
      Repo.delete_all(from(t in "tokens", where: t.jti == ^request.token_id))

      assert {:error, %Invalid{}} = Cases.get_github_manual_request(request.id, actor: poc)
    end

    test "records the answer as the POC once, and is spent", %{
      poc: poc,
      case: case_record,
      request: request,
      token: token
    } do
      completed =
        Cases.complete_github_manual_request!(locate!(request), token, answer(), service())

      assert %DateTime{} = completed.completed_at

      assert [%{ghsa_id: @ghsa_id, owner: "acme", repo: "other_lib"}] =
               Cases.list_github_advisory_links!(
                 actor: poc,
                 query: [filter: [case_id: case_record.id]]
               )

      assert %{purpose: "revocation"} = Ash.get!(Token, request.token_id, authorize?: false)

      assert {:error, %Forbidden{}} =
               Cases.complete_github_manual_request(locate!(request), token, answer(), service())

      assert {:error, %Forbidden{}} =
               Cases.fetch_github_manual_request(locate!(request), token, service())
    end

    test "an answer of another repository or advisory records nothing", %{
      poc: poc,
      case: case_record,
      request: request,
      token: token
    } do
      other_repo =
        answer(%{
          "html_url" => "https://github.com/acme/acme_lib/security/advisories/#{@ghsa_id}"
        })

      assert {:error, %Invalid{errors: [%{field: :answer}]}} =
               Cases.complete_github_manual_request(
                 locate!(request),
                 token,
                 other_repo,
                 service()
               )

      other_ghsa =
        answer(%{
          "ghsa_id" => "GHSA-2cfg-hjmp-qrvw",
          "html_url" => "https://github.com/acme/other_lib/security/advisories/GHSA-2cfg-hjmp-qrvw"
        })

      assert {:error, %Invalid{errors: [%{field: :answer}]}} =
               Cases.complete_github_manual_request(
                 locate!(request),
                 token,
                 other_ghsa,
                 service()
               )

      assert [] =
               Cases.list_github_advisory_links!(
                 actor: poc,
                 query: [filter: [case_id: case_record.id]]
               )

      assert is_nil(Cases.get_github_manual_request!(request.id, actor: poc).completed_at)
    end

    test "the attested link actions refuse a caller without the stamp", %{
      poc: poc,
      case: case_record
    } do
      assert {:error, %Forbidden{}} =
               Cases.link_github_advisory_attested(%{case_id: case_record.id, advisory: answer()},
                 actor: poc
               )
    end
  end
end
