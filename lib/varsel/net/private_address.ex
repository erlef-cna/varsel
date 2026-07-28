# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Net.PrivateAddress do
  @moduledoc """
  Classifies IP addresses as private / non-publicly-routable.

  Used to keep server-side egress (git clones of a case's `repo_url`) on the
  public internet: a host that resolves only to loopback, RFC 1918, link-local,
  unique-local, CGNAT, or other special-use ranges is treated as private.

  An IPv6 address that *embeds* an IPv4 one — IPv4-mapped, IPv4-compatible,
  6to4, NAT64 — is classified by the address it carries, since the outer
  prefix can be globally routable while the address inside it is not.

  Resolution goes through `:inet.getaddrs/2` (the system resolver /
  `getaddrinfo`).
  """

  # Special-use / non-public IPv4 ranges (RFC 5735, 1918, 6598, 3927, …).
  @v4_private ~w(
    0.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.0.0.0/24
    192.0.2.0/24
    192.31.196.0/24
    192.52.193.0/24
    192.88.99.0/24
    192.168.0.0/16
    192.175.48.0/24
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
  )

  # Special-use / non-public IPv6 ranges, from the IANA IPv6 Special-Purpose
  # Address Registry. The prefixes that *embed* an IPv4 address are not here:
  # they are unwrapped and the embedded address classified instead, because
  # the IPv6 prefix is global while the address inside it need not be.
  #
  # `fec0::/10` is deprecated (RFC 3879) rather than assigned, so it is absent
  # from most current listings, but it is reserved and never globally routed.
  #
  # Teredo (`2001::/32`) also embeds IPv4, but the client address it carries is
  # obfuscated and its server address says nothing about where traffic lands,
  # so the prefix is refused outright instead.
  @v6_private ~w(
    ::1/128
    ::/128
    fc00::/7
    fe80::/10
    ff00::/8
    100::/64
    2001::/32
    2001:20::/28
    2001:db8::/32
    3fff::/20
    5f00::/16
    fec0::/10
  )

  @blocklist Enum.map(@v4_private ++ @v6_private, &CIDR.parse/1)

  @doc """
  Returns `true` if every address the host resolves to is private, or if the
  host cannot be resolved to any address at all (fail closed).

  `host` is a URL host string — an IP literal (`"127.0.0.1"`, `"::1"`) or a
  DNS name (`"github.com"`). For a name, both A and AAAA records are resolved
  and *every* returned address must be public for the host to count as public.
  """
  @spec private_host?(String.t()) :: boolean()
  def private_host?(host) when is_binary(host) do
    case resolve(host) do
      # No address at all → fail closed (treat as private).
      [] -> true
      addresses -> Enum.any?(addresses, &private_address?/1)
    end
  end

  @doc "Returns `true` if the given `:inet` address tuple is private/special-use."
  @spec private_address?(:inet.ip_address()) :: boolean()
  def private_address?({_, _, _, _} = v4), do: any_match?(v4)

  # IPv4-mapped (::ffff:a.b.c.d) and the deprecated IPv4-compatible (::a.b.c.d)
  # forms. The latter also covers `::` and `::1`, which unwrap to 0.0.0.0 and
  # 0.0.0.1 and are private under `0.0.0.0/8`.
  def private_address?({0, 0, 0, 0, 0, 0xFFFF, ab, cd}), do: private_address?(v4(ab, cd))
  def private_address?({0, 0, 0, 0, 0, 0, ab, cd}), do: private_address?(v4(ab, cd))

  # 6to4 (2002:a.b.c.d::/48) carries the v4 address of the tunnel endpoint in
  # the two groups after the prefix.
  def private_address?({0x2002, ab, cd, _, _, _, _, _}), do: private_address?(v4(ab, cd))

  # NAT64 (64:ff9b::/96 well-known, 64:ff9b:1::/48 local-use) embeds the
  # translated v4 address in the last two groups. The prefix itself is global,
  # so what matters is what it translates *to*.
  def private_address?({0x64, 0xFF9B, 0, 0, 0, 0, ab, cd}), do: private_address?(v4(ab, cd))
  def private_address?({0x64, 0xFF9B, 1, _, _, _, ab, cd}), do: private_address?(v4(ab, cd))

  def private_address?({_, _, _, _, _, _, _, _} = v6), do: any_match?(v6)

  # The two 16-bit groups an embedded IPv4 address occupies, as a v4 tuple.
  defp v4(ab, cd), do: {div(ab, 256), rem(ab, 256), div(cd, 256), rem(cd, 256)}

  defp any_match?(address) do
    Enum.any?(@blocklist, fn cidr ->
      match?({:ok, true}, CIDR.match(cidr, address))
    end)
  end

  # An IP literal host resolves to itself; a DNS name is looked up (A + AAAA)
  # via the system resolver. Returns a (possibly empty) list of address tuples.
  defp resolve(host) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, address} -> [address]
      {:error, _} -> getaddrs(charlist, :inet) ++ getaddrs(charlist, :inet6)
    end
  end

  defp getaddrs(charlist, family) do
    case :inet.getaddrs(charlist, family) do
      {:ok, addresses} -> addresses
      {:error, _} -> []
    end
  end
end
