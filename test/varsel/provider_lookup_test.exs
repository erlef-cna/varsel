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
end
