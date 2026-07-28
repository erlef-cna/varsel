# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Net.PrivateAddressTest do
  use ExUnit.Case, async: true

  alias Varsel.Net.PrivateAddress

  defp private?(literal) do
    {:ok, address} = literal |> String.to_charlist() |> :inet.parse_address()
    PrivateAddress.private_address?(address)
  end

  defp assert_private(literals) do
    for literal <- literals do
      assert private?(literal), "expected #{literal} to be private"
    end
  end

  defp refute_private(literals) do
    for literal <- literals do
      refute private?(literal), "expected #{literal} to be public"
    end
  end

  describe "IPv4" do
    test "special-use ranges are private, at both bounds and inside" do
      assert_private([
        # 0.0.0.0/8 — this host
        "0.0.0.0",
        "0.255.255.255",
        # 10.0.0.0/8 — RFC 1918
        "10.0.0.0",
        "10.1.2.3",
        "10.255.255.255",
        # 100.64.0.0/10 — CGNAT
        "100.64.0.0",
        "100.127.255.255",
        # 127.0.0.0/8 — loopback
        "127.0.0.0",
        "127.0.0.1",
        "127.255.255.255",
        # 169.254.0.0/16 — link-local, and the cloud metadata endpoint
        "169.254.0.0",
        "169.254.169.254",
        "169.254.255.255",
        # 172.16.0.0/12 — RFC 1918
        "172.16.0.0",
        "172.31.255.255",
        # 192.0.0.0/24 — IETF protocol assignments
        "192.0.0.0",
        "192.0.0.255",
        # 192.0.2.0/24 — TEST-NET-1
        "192.0.2.1",
        # 192.31.196.0/24 — AS112
        "192.31.196.1",
        # 192.52.193.0/24 — AMT
        "192.52.193.1",
        # 192.88.99.0/24 — 6to4 relay anycast
        "192.88.99.1",
        # 192.168.0.0/16 — RFC 1918
        "192.168.0.0",
        "192.168.1.1",
        "192.168.255.255",
        # 192.175.48.0/24 — AS112 direct delegation
        "192.175.48.1",
        # 198.18.0.0/15 — benchmarking
        "198.18.0.0",
        "198.19.255.255",
        # 198.51.100.0/24 — TEST-NET-2
        "198.51.100.1",
        # 203.0.113.0/24 — TEST-NET-3
        "203.0.113.1",
        # 224.0.0.0/4 — multicast
        "224.0.0.0",
        "239.255.255.255",
        # 240.0.0.0/4 — reserved, incl. broadcast
        "240.0.0.0",
        "255.255.255.255"
      ])
    end

    test "ordinary public addresses are public" do
      refute_private([
        "1.1.1.1",
        "8.8.8.8",
        "9.255.255.255",
        "11.0.0.0",
        "93.184.216.34",
        "140.82.121.3",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "223.255.255.255"
      ])
    end
  end

  describe "IPv6" do
    test "special-use ranges are private" do
      assert_private([
        # ::/128 unspecified and ::1/128 loopback
        "::",
        "::1",
        # 100::/64 — discard prefix
        "100::",
        "100::ffff:ffff:ffff:ffff",
        # 2001::/32 — Teredo
        "2001::",
        "2001:0:ffff:ffff:ffff:ffff:ffff:ffff",
        # 2001:20::/28 — ORCHIDv2
        "2001:20::",
        "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff",
        # 2001:db8::/32 — documentation
        "2001:db8::",
        "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
        # 3fff::/20 — documentation (RFC 9637)
        "3fff::",
        "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff",
        # 5f00::/16 — SRv6
        "5f00::",
        "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        # fc00::/7 — unique local
        "fc00::",
        "fd00::1",
        "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        # fe80::/10 — link-local
        "fe80::",
        "fe80::1",
        "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        # fec0::/10 — deprecated site-local (RFC 3879), still reserved
        "fec0::",
        "fec0::1",
        "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        # ff00::/8 — multicast
        "ff00::",
        "ff02::1",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
      ])
    end

    test "global unicast addresses are public" do
      refute_private([
        "2001:4860:4860::8888",
        "2606:2800:220:1:248:1893:25c8:1946",
        "2620:fe::fe",
        # Just outside the documentation and Teredo prefixes.
        "2001:1::1",
        "2001:db9::1",
        "2001:30::1",
        "4000::1",
        # Outside 2000::/3 but not otherwise reserved — global unicast is
        # defined by what is *not* assigned, not by that prefix.
        "6000::1"
      ])
    end
  end

  # The IPv6 prefix can be globally routable while the address it carries is
  # not, so these are classified by what they embed rather than by prefix.
  describe "embedded IPv4" do
    test "IPv4-mapped (::ffff:a.b.c.d) follows the embedded address" do
      assert_private(["::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"])
      refute_private(["::ffff:8.8.8.8", "::ffff:93.184.216.34"])
    end

    test "IPv4-compatible (::a.b.c.d) follows the embedded address" do
      assert_private(["::127.0.0.1", "::10.0.0.1"])
      refute_private(["::8.8.8.8"])
    end

    test "6to4 (2002:a.b.c.d::/48) follows the embedded address" do
      assert_private(["2002:7f00:1::", "2002:a00:1::1", "2002:c0a8:101::"])
      refute_private(["2002:808:808::", "2002:5db8:d822::1"])
    end

    test "NAT64 (64:ff9b::/96) follows the translated address" do
      assert_private(["64:ff9b::127.0.0.1", "64:ff9b::10.0.0.1"])
      refute_private(["64:ff9b::8.8.8.8"])
    end

    test "local-use NAT64 (64:ff9b:1::/48) follows the translated address" do
      assert_private(["64:ff9b:1::127.0.0.1", "64:ff9b:1::10.0.0.1"])
      refute_private(["64:ff9b:1::8.8.8.8"])
    end
  end

  describe "private_host?/1" do
    test "an unresolvable host fails closed" do
      assert PrivateAddress.private_host?("nonexistent.invalid")
    end

    test "an IP literal is classified without a lookup" do
      assert PrivateAddress.private_host?("127.0.0.1")
      assert PrivateAddress.private_host?("::1")
      refute PrivateAddress.private_host?("93.184.216.34")
    end

    test "localhost resolves through the hosts file to loopback" do
      assert PrivateAddress.private_host?("localhost")
    end
  end
end
