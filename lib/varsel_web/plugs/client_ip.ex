# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.ClientIp do
  @moduledoc """
  Rewrites `remote_ip` from `x-forwarded-for`, but only when the request came
  from a proxy we trust.

  `RemoteIp` alone classifies the addresses *inside* the header and never the
  peer that sent it, so it believes `x-forwarded-for` from anybody who can
  open a connection. The endpoint binds `::` and Fly machines share a private
  network, so that is not only the edge proxy. This runs `RemoteIp` when the
  peer is a trusted proxy and leaves `remote_ip` as the peer otherwise.

  Trusted peers default to the private/loopback ranges the platform proxies
  from; `:proxies` overrides that for a deployment fronted from elsewhere.
  """
  @behaviour Plug

  # Loopback, RFC 1918, link-local, IPv6 unique-local and the IPv4-mapped
  # forms of the above, which is how a dual-stack listener sees them.
  @default_proxies ~w[
    127.0.0.0/8
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
    169.254.0.0/16
    ::1/128
    fc00::/7
    fe80::/10
    ::ffff:127.0.0.0/104
    ::ffff:10.0.0.0/104
    ::ffff:172.16.0.0/108
    ::ffff:192.168.0.0/112
  ]

  @impl Plug
  def init(opts) do
    {proxies, remote_ip_opts} = Keyword.pop(opts, :proxies, @default_proxies)

    %{
      proxies: Enum.map(proxies, &RemoteIp.Block.parse!/1),
      remote_ip: RemoteIp.init(remote_ip_opts)
    }
  end

  @impl Plug
  def call(conn, %{proxies: proxies, remote_ip: remote_ip_opts}) do
    if trusted?(conn.remote_ip, proxies) do
      RemoteIp.call(conn, remote_ip_opts)
    else
      conn
    end
  end

  defp trusted?(peer, proxies) do
    encoded = RemoteIp.Block.encode(peer)
    Enum.any?(proxies, &RemoteIp.Block.contains?(&1, encoded))
  end
end
