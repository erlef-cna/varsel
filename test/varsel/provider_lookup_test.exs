# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Accounts.ProviderLookupTest do
  use ExUnit.Case, async: false

  alias Varsel.Accounts.GitHub
  alias Varsel.HexPm

  describe "GitHub.user/1" do
    test "returns the login as GitHub spells it" do
      Req.Test.stub(GitHub, fn conn ->
        assert conn.request_path == "/users/AliCe"
        Req.Test.json(conn, %{"login" => "alice"})
      end)

      assert GitHub.user("AliCe") == {:ok, "alice"}
    end

    test "a missing account is not an error" do
      Req.Test.stub(GitHub, &Plug.Conn.send_resp(&1, 404, "{}"))

      assert GitHub.user("nobody") == :not_found
    end
  end

  describe "HexPm.user/1" do
    setup do
      Application.put_env(:varsel, :hex_stub_users, ["alice"])
      on_exit(fn -> Application.delete_env(:varsel, :hex_stub_users) end)
    end

    test "returns the username as hex.pm spells it" do
      assert HexPm.user("AliCe") == {:ok, "alice"}
    end

    test "a missing account is not an error" do
      assert HexPm.user("nobody") == :not_found
    end
  end

  describe "HexPm.contact/1" do
    setup do
      original = Application.get_env(:varsel, :hex_signing_key)

      on_exit(fn ->
        Application.put_env(:varsel, :hex_signing_key, original)
        Application.delete_env(:varsel, :hex)
      end)

      :ok
    end

    test "returns who the account belongs to" do
      Req.Test.stub(HexPm, fn conn ->
        assert conn.request_path == "/api/users/AliCe/contact"

        Req.Test.json(conn, %{
          "username" => "alice",
          "name" => "Alice",
          "email" => "alice@example.com"
        })
      end)

      assert HexPm.contact("AliCe") ==
               {:ok, %{username: "alice", name: "Alice", email: "alice@example.com"}}
    end

    test "authenticates with a service token addressed to the instance sign-in uses" do
      Application.put_env(:varsel, :hex, base_url: "http://localhost:4000/")

      Req.Test.stub(HexPm, fn conn ->
        ["Bearer " <> token] = Plug.Conn.get_req_header(conn, "authorization")

        assert %{"aud" => "http://localhost:4000", "iss" => "varsel"} =
                 JOSE.JWT.peek_payload(token).fields

        Req.Test.json(conn, %{"username" => "alice", "name" => "Alice"})
      end)

      assert {:ok, _contact} = HexPm.contact("alice")
    end

    test "looks up an email address as one encoded path segment" do
      Req.Test.stub(HexPm, fn conn ->
        assert conn.request_path == "/api/users/alice%40example.com/contact"

        Req.Test.json(conn, %{
          "username" => "alice",
          "name" => "Alice",
          "email" => "alice@example.com"
        })
      end)

      assert {:ok, %{username: "alice"}} = HexPm.contact("alice@example.com")
    end

    test "an account without a verified address has no email" do
      Req.Test.stub(HexPm, &Req.Test.json(&1, %{"username" => "alice", "name" => "alice"}))

      assert HexPm.contact("alice") == {:ok, %{username: "alice", name: "alice", email: nil}}
    end

    test "a missing account is not an error" do
      Req.Test.stub(HexPm, &Plug.Conn.send_resp(&1, 404, "{}"))

      assert HexPm.contact("nobody") == :not_found
    end

    test "a refused token is an error" do
      Req.Test.stub(HexPm, &Plug.Conn.send_resp(&1, 401, "{}"))

      assert {:error, %Req.Response{status: 401}} = HexPm.contact("alice")
    end

    test "fails closed without a signing key" do
      Application.delete_env(:varsel, :hex_signing_key)

      assert HexPm.contact("alice") == {:error, :not_configured}
    end
  end
end
