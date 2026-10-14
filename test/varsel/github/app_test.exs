# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.GitHub.AppTest do
  # Swaps the :github config for the unconfigured case.
  use ExUnit.Case, async: false

  alias Varsel.GitHub.App
  alias Varsel.GitHub.Client

  defp claims(conn) do
    ["Bearer " <> jwt] = Plug.Conn.get_req_header(conn, "authorization")

    public_key =
      Application.fetch_env!(:varsel, :github)[:private_key]
      |> JOSE.JWK.from_pem()
      |> JOSE.JWK.to_public()

    assert {true, %JOSE.JWT{fields: claims}, %JOSE.JWS{alg: {_module, :RS256}}} =
             JOSE.JWT.verify_strict(public_key, ["RS256"], jwt)

    claims
  end

  describe "the JWT" do
    test "is signed by the App's key and is valid from one minute ago for ten minutes" do
      Req.Test.stub(Client, fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/orgs/erlef-cna/installation"

        now = System.system_time(:second)
        claims = claims(conn)

        assert claims["iss"] == "424242"
        assert_in_delta claims["iat"], now - 60, 2
        assert_in_delta claims["exp"], now + 600, 2

        Req.Test.json(conn, %{
          "id" => 11,
          "account" => %{"login" => "erlef-cna"},
          "target_type" => "Organization",
          "repository_selection" => "all"
        })
      end)

      assert App.org_installation("erlef-cna") ==
               {:ok, %{id: 11, account: "erlef-cna", kind: :organization, repository_selection: :all}}
    end

    test "is read from a key with escaped newlines" do
      config = Application.fetch_env!(:varsel, :github)
      escaped = String.replace(config[:private_key], "\n", "\\n")
      Application.put_env(:varsel, :github, Keyword.put(config, :private_key, escaped))
      on_exit(fn -> Application.put_env(:varsel, :github, config) end)

      assert App.configured?()
      assert {:ok, _jwt} = App.jwt()
    end
  end

  describe "repository_installation/2" do
    test "describes a user's installation that covers selected repositories" do
      Req.Test.stub(Client, fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/repos/jdoe/lib/installation"
        assert claims(conn)["iss"] == "424242"

        Req.Test.json(conn, %{
          "id" => 12,
          "account" => %{"login" => "jdoe"},
          "target_type" => "User",
          "repository_selection" => "selected"
        })
      end)

      assert App.repository_installation("jdoe", "lib") ==
               {:ok, %{id: 12, account: "jdoe", kind: :user, repository_selection: :selected}}
    end

    test "answers :not_installed when GitHub answers 404" do
      Req.Test.stub(Client, fn conn ->
        assert conn.request_path == "/repos/acme/lib/installation"
        conn |> Plug.Conn.put_status(404) |> Req.Test.json(%{"message" => "Not Found"})
      end)

      assert App.repository_installation("acme", "lib") == :not_installed
    end
  end

  describe "mint/1" do
    test "mints an installation token with the JWT" do
      Req.Test.stub(Client, fn conn ->
        assert conn.method == "POST"
        assert conn.request_path == "/app/installations/11/access_tokens"
        assert claims(conn)["iss"] == "424242"

        conn
        |> Plug.Conn.put_status(201)
        |> Req.Test.json(%{"token" => "ghs_minted", "expires_at" => "2026-10-14T13:00:00Z"})
      end)

      assert App.mint(11) == {:ok, %{token: "ghs_minted", expires_at: ~U[2026-10-14 13:00:00Z]}}
    end
  end

  describe "user_installations/1" do
    test "lists the installations the user's token reaches" do
      Req.Test.stub(Client, fn conn ->
        assert conn.method == "GET"
        assert conn.request_path == "/user/installations"
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_user"]

        Req.Test.json(conn, %{
          "total_count" => 2,
          "installations" => [%{"id" => 11}, %{"id" => 12}]
        })
      end)

      assert App.user_installations("gho_user") == {:ok, [11, 12]}
    end

    test "answers :unauthorized when GitHub refuses the token" do
      Req.Test.stub(Client, fn conn ->
        assert conn.request_path == "/user/installations"
        conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
      end)

      assert App.user_installations("gho_expired") == {:error, :unauthorized}
    end
  end

  describe "without a private key" do
    setup do
      config = Application.fetch_env!(:varsel, :github)
      Application.put_env(:varsel, :github, Keyword.delete(config, :private_key))
      on_exit(fn -> Application.put_env(:varsel, :github, config) end)
    end

    test "the App is inert and sends no request" do
      Req.Test.stub(Client, fn _conn -> flunk("the App sent a request") end)

      refute App.configured?()
      assert App.repository_installation("acme", "lib") == :not_installed
      assert App.org_installation("acme") == :not_installed
      assert App.mint(11) == {:error, :not_configured}
    end
  end
end
