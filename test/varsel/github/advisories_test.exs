# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.AdvisoriesTest do
  use ExUnit.Case, async: false

  alias Varsel.GitHub.Advisories
  alias Varsel.Test.GitHubApi

  describe "parse/1" do
    test "reads a repository advisory URL" do
      assert Advisories.parse("https://github.com/erlang/otp/security/advisories/GHSA-pwvh-c689-f8q5") ==
               {:ok, %{owner: "erlang", repo: "otp", ghsa_id: "GHSA-pwvh-c689-f8q5"}}
    end

    test "reads a global advisory URL" do
      assert Advisories.parse("https://github.com/advisories/GHSA-pwvh-c689-f8q5") ==
               {:ok, %{ghsa_id: "GHSA-pwvh-c689-f8q5"}}
    end

    test "reads a bare id and spells it as GitHub does" do
      assert Advisories.parse("  ghsa-PWVH-c689-f8q5 ") ==
               {:ok, %{ghsa_id: "GHSA-pwvh-c689-f8q5"}}
    end

    test "refuses anything else" do
      assert Advisories.parse("https://github.com/erlang/otp") == :error
      assert Advisories.parse("https://example.com/advisories/GHSA-pwvh-c689-f8q5") == :error

      assert Advisories.parse("https://github.com/erlang/otp/security/advisories/CVE-2026-1") ==
               :error

      assert Advisories.parse("GHSA-1111-1111-1111") == :error
      assert Advisories.parse("") == :error
    end
  end

  describe "fetch/4" do
    test "reads the repository advisory as the user whose token is given" do
      GitHubApi.stub(fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/repos/erlang/otp/security-advisories/GHSA-pwvh-c689-f8q5"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_token"]
        assert Plug.Conn.get_req_header(conn, "x-github-api-version") == ["2022-11-28"]

        Req.Test.json(conn, %{"ghsa_id" => "GHSA-pwvh-c689-f8q5", "state" => "draft"})
      end)

      assert Advisories.fetch("erlang", "otp", "GHSA-pwvh-c689-f8q5", token: "gho_token") ==
               {:ok, %{"ghsa_id" => "GHSA-pwvh-c689-f8q5", "state" => "draft"}}
    end

    test "reads anonymously without a token" do
      GitHubApi.stub(fn conn ->
        assert Plug.Conn.get_req_header(conn, "authorization") == []
        Req.Test.json(conn, %{"ghsa_id" => "GHSA-pwvh-c689-f8q5"})
      end)

      assert {:ok, _advisory} = Advisories.fetch("erlang", "otp", "GHSA-pwvh-c689-f8q5")
    end

    test "an advisory that does not exist or may not be seen is not found" do
      GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, ~s({"message":"Not Found"})))

      assert Advisories.fetch("erlang", "otp", "GHSA-pwvh-c689-f8q5", token: "gho_token") ==
               :not_found
    end

    test "a token GitHub no longer accepts is unauthorized" do
      GitHubApi.stub(fn conn ->
        conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
      end)

      assert Advisories.fetch("erlang", "otp", "GHSA-pwvh-c689-f8q5", token: "gho_revoked") ==
               {:error, :unauthorized}
    end

    test "surfaces any other refusal" do
      GitHubApi.stub(fn conn ->
        conn |> Plug.Conn.put_status(403) |> Req.Test.json(%{"message" => "rate limited"})
      end)

      assert Advisories.fetch("erlang", "otp", "GHSA-pwvh-c689-f8q5") ==
               {:error, {:http, 403, %{"message" => "rate limited"}}}
    end
  end

  describe "update/5, create/4 and report/4" do
    test "update patches the advisory as the user and answers what GitHub now holds" do
      GitHubApi.stub(fn conn ->
        assert conn.method == "PATCH"
        assert conn.request_path == "/repos/erlang/otp/security-advisories/GHSA-pwvh-c689-f8q5"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_token"]
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        assert JSON.decode!(body) == %{"summary" => "New title"}

        Req.Test.json(conn, %{"ghsa_id" => "GHSA-pwvh-c689-f8q5", "summary" => "New title"})
      end)

      assert {:ok, %{"summary" => "New title"}} =
               Advisories.update(
                 "erlang",
                 "otp",
                 "GHSA-pwvh-c689-f8q5",
                 %{"summary" => "New title"},
                 token: "gho_token"
               )
    end

    test "create opens a draft advisory as the user" do
      GitHubApi.stub(fn conn ->
        assert conn.method == "POST"
        assert conn.request_path == "/repos/acme/acme_lib/security-advisories"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_token"]

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"ghsa_id" => "GHSA-2cfg-hjmp-qrvw", "state" => "draft"})
      end)

      assert {:ok, %{"state" => "draft"}} =
               Advisories.create("acme", "acme_lib", %{"summary" => "s", "description" => "d"}, token: "gho_token")
    end

    test "report posts the private report and answers the advisory GitHub opened" do
      GitHubApi.stub(fn conn ->
        assert conn.method == "POST"
        assert conn.request_path == "/repos/acme/acme_lib/security-advisories/reports"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_token"]

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"ghsa_id" => "GHSA-2cfg-hjmp-qrvw", "state" => "triage"})
      end)

      assert {:ok, %{"state" => "triage"}} =
               Advisories.report("acme", "acme_lib", %{"summary" => "s", "description" => "d"}, token: "gho_token")
    end

    test "a write without a token never goes out" do
      GitHubApi.stub(fn _conn -> flunk("GitHub was asked") end)

      assert_raise KeyError, fn ->
        Advisories.update("erlang", "otp", "GHSA-pwvh-c689-f8q5", %{}, [])
      end
    end

    test "a write GitHub refuses is an error with its message" do
      GitHubApi.stub(fn conn ->
        conn |> Plug.Conn.put_status(422) |> Req.Test.json(%{"message" => "Validation Failed"})
      end)

      assert {:error, {:http, 422, %{"message" => "Validation Failed"}}} =
               Advisories.update("erlang", "otp", "GHSA-pwvh-c689-f8q5", %{}, token: "gho_token")
    end
  end

  describe "private_reporting_enabled?/3" do
    test "answers whether the repository takes private reports" do
      GitHubApi.stub(fn conn ->
        assert conn.request_path == "/repos/acme/acme_lib/private-vulnerability-reporting"
        Req.Test.json(conn, %{"enabled" => false})
      end)

      assert Advisories.private_reporting_enabled?("acme", "acme_lib", token: "gho_token") ==
               {:ok, false}
    end

    test "an unknown repository is not found" do
      GitHubApi.stub(&Plug.Conn.send_resp(&1, 404, "{}"))

      assert Advisories.private_reporting_enabled?("acme", "gone") == :not_found
    end
  end

  describe "fetch_global/2" do
    test "reads the global database entry" do
      GitHubApi.stub(fn conn ->
        assert conn.request_path == "/advisories/GHSA-pwvh-c689-f8q5"
        Req.Test.json(conn, %{"ghsa_id" => "GHSA-pwvh-c689-f8q5", "type" => "reviewed"})
      end)

      assert {:ok, %{"type" => "reviewed"}} = Advisories.fetch_global("GHSA-pwvh-c689-f8q5")
    end
  end
end
