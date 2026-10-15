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
        assert {conn.method, conn.request_path} == {"GET", "/app/installations"}

        now = System.system_time(:second)
        claims = claims(conn)

        assert claims["iss"] == "424242"
        assert_in_delta claims["iat"], now - 60, 2
        assert_in_delta claims["exp"], now + 600, 2

        Req.Test.json(conn, [])
      end)

      assert App.installations() == {:ok, []}
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

  describe "installations/0" do
    test "describes every installation from all pages" do
      Req.Test.stub(Client, fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        assert {conn.method, conn.request_path} == {"GET", "/app/installations"}
        assert claims(conn)["iss"] == "424242"
        assert conn.query_params["per_page"] == "100"

        case conn.query_params["page"] do
          "1" ->
            conn
            |> Plug.Conn.put_resp_header(
              "link",
              ~s(<https://api.github.com/app/installations?per_page=100&page=2>; rel="next", ) <>
                ~s(<https://api.github.com/app/installations?per_page=100&page=2>; rel="last")
            )
            |> Req.Test.json([
              %{
                "id" => 11,
                "account" => %{"login" => "erlef-cna"},
                "target_type" => "Organization",
                "repository_selection" => "all",
                "suspended_at" => nil
              }
            ])

          "2" ->
            Req.Test.json(conn, [
              %{
                "id" => 12,
                "account" => %{"login" => "jdoe"},
                "target_type" => "User",
                "repository_selection" => "selected",
                "suspended_at" => "2026-10-01T12:00:00Z"
              }
            ])
        end
      end)

      assert App.installations() ==
               {:ok,
                [
                  %{
                    id: 11,
                    account: "erlef-cna",
                    kind: :organization,
                    repository_selection: :all,
                    suspended_at: nil
                  },
                  %{
                    id: 12,
                    account: "jdoe",
                    kind: :user,
                    repository_selection: :selected,
                    suspended_at: ~U[2026-10-01 12:00:00Z]
                  }
                ]}
    end

    test "answers :unauthorized when GitHub refuses the JWT" do
      Req.Test.stub(Client, fn conn ->
        assert conn.request_path == "/app/installations"
        conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
      end)

      assert App.installations() == {:error, :unauthorized}
    end
  end

  describe "installation_repositories/1" do
    test "lists the repositories the installation token reaches" do
      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/installation/repositories"}
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer ghs_installation"]

        Req.Test.json(conn, %{
          "total_count" => 1,
          "repositories" => [%{"name" => "lib", "owner" => %{"login" => "jdoe"}}]
        })
      end)

      assert App.installation_repositories("ghs_installation") ==
               {:ok, [%{owner: "jdoe", repo: "lib"}]}
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
          "total_count" => 1,
          "installations" => [
            %{
              "id" => 12,
              "account" => %{"login" => "jdoe"},
              "target_type" => "User",
              "repository_selection" => "selected",
              "suspended_at" => nil
            }
          ]
        })
      end)

      assert App.user_installations("gho_user") ==
               {:ok,
                [
                  %{
                    id: 12,
                    account: "jdoe",
                    kind: :user,
                    repository_selection: :selected,
                    suspended_at: nil
                  }
                ]}
    end

    test "answers :unauthorized when GitHub refuses the token" do
      Req.Test.stub(Client, fn conn ->
        assert conn.request_path == "/user/installations"
        conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"message" => "Bad credentials"})
      end)

      assert App.user_installations("gho_expired") == {:error, :unauthorized}
    end
  end

  describe "user_installation_repositories/2" do
    test "lists the repositories of the installation that the user's token reaches" do
      Req.Test.stub(Client, fn conn ->
        assert {conn.method, conn.request_path} == {"GET", "/user/installations/12/repositories"}
        assert Plug.Conn.get_req_header(conn, "authorization") == ["Bearer gho_user"]

        Req.Test.json(conn, %{
          "total_count" => 1,
          "repositories" => [%{"name" => "lib", "owner" => %{"login" => "jdoe"}}]
        })
      end)

      assert App.user_installation_repositories("gho_user", 12) ==
               {:ok, [%{owner: "jdoe", repo: "lib"}]}
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
      assert App.installations() == {:error, :not_configured}
      assert App.mint(11) == {:error, :not_configured}
    end
  end
end
