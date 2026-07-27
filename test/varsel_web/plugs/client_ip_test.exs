# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.ClientIpTest do
  use ExUnit.Case, async: true

  import Plug.Test

  alias VarselWeb.Plugs.ClientIp

  defp client_ip(peer, forwarded_for, opts \\ []) do
    opts = ClientIp.init(Keyword.put_new(opts, :headers, ~w[x-forwarded-for]))

    %{conn(:get, "/") | remote_ip: peer}
    |> then(fn conn ->
      if forwarded_for,
        do: Plug.Conn.put_req_header(conn, "x-forwarded-for", forwarded_for),
        else: conn
    end)
    |> ClientIp.call(opts)
    |> Map.fetch!(:remote_ip)
    |> :inet.ntoa()
    |> to_string()
  end

  describe "a request through a trusted proxy" do
    test "reports the client the proxy names" do
      assert client_ip({10, 0, 0, 7}, "203.0.113.9") == "203.0.113.9"
      assert client_ip({127, 0, 0, 1}, "203.0.113.9") == "203.0.113.9"
    end

    test "walks past further proxy hops to the client" do
      assert client_ip({10, 0, 0, 1}, "203.0.113.9, 10.0.0.7") == "203.0.113.9"
    end

    test "falls back to the peer when the header says nothing" do
      assert client_ip({10, 0, 0, 7}, nil) == "10.0.0.7"
    end
  end

  # The reason this plug exists. `RemoteIp` on its own classifies the addresses
  # inside the header and never the peer, so it believes any caller that can
  # reach the endpoint — and Fly machines share a private network with us.
  describe "a request straight from the internet" do
    test "ignores the address it claims for itself" do
      assert client_ip({198, 51, 100, 22}, "1.2.3.4") == "198.51.100.22"
      assert client_ip({198, 51, 100, 22}, "1.2.3.4, 5.6.7.8") == "198.51.100.22"
    end

    test "ignores a claim dressed up as a private hop" do
      assert client_ip({198, 51, 100, 22}, "10.0.0.5") == "198.51.100.22"
    end

    test "is unaffected by a header it did not send" do
      assert client_ip({198, 51, 100, 22}, nil) == "198.51.100.22"
    end
  end

  test "an operator can name the proxies to trust" do
    fronted = [proxies: ~w[198.51.100.0/24]]

    assert client_ip({198, 51, 100, 22}, "1.2.3.4", fronted) == "1.2.3.4"
    assert client_ip({10, 0, 0, 7}, "1.2.3.4", fronted) == "10.0.0.7"
  end
end
