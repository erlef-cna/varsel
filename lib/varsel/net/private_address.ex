# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Net.PrivateAddress do
  @moduledoc """
  Classifies IP addresses as private / non-publicly-routable.

  Used to keep server-side egress (git clones of a case's `repo_url`) on the
  public internet: a host that resolves only to loopback, RFC 1918, link-local,
  unique-local, CGNAT, or other special-use ranges is treated as private.

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
    192.88.99.0/24
    192.168.0.0/16
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    255.255.255.255/32
  )

  # Special-use / non-public IPv6 ranges. `::ffff:0:0/96` (IPv4-mapped) is
  # handled separately by unwrapping to the embedded v4 address.
  @v6_private ~w(
    ::1/128
    ::/128
    fc00::/7
    fe80::/10
    ff00::/8
    2001:db8::/32
    100::/64
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

  # IPv4-mapped IPv6 (::ffff:a.b.c.d): unwrap and classify the embedded v4.
  def private_address?({0, 0, 0, 0, 0, 0xFFFF, ab, cd}) do
    private_address?({div(ab, 256), rem(ab, 256), div(cd, 256), rem(cd, 256)})
  end

  def private_address?({_, _, _, _, _, _, _, _} = v6), do: any_match?(v6)

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
