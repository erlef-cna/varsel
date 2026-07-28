# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Cases.Derivation.PinnedTransport do
  @moduledoc """
  Builds an `Exgit.Transport.HTTP` that keeps connecting to the address it
  checked.

  The host is resolved here, and the connection pinned to what that lookup
  returned: the request URL carries the **address**, and the hostname is put
  back as a `Host` header, as the TLS server name, and as the name the
  certificate must match. There is no second lookup between the check and the
  connection for DNS to answer differently, and the server still has to
  present a certificate valid for the name the case names — pinning to an IP
  does not weaken that.

  Only the first hop is pinned. Redirects stay off (exgit's default), so
  there is no later hop that could resolve somewhere else.
  """

  alias Exgit.Transport
  alias Varsel.Net.PrivateAddress

  @type error :: :private_address | :unresolvable | :invalid_url

  @doc """
  A transport for `repo_url` pinned to a public address, or `{:error,
  reason}` when the host does not resolve to one right now.

  `repo_url` must be `https://` or `http://` with a host; anything else is
  `{:error, :invalid_url}`.
  """
  @spec build(String.t(), keyword()) :: {:ok, Transport.HTTP.t()} | {:error, error()}
  def build(repo_url, opts \\ []) do
    with {:ok, uri} <- web_uri(repo_url),
         {:ok, address} <- public_address(uri.host) do
      {:ok, transport(uri, address, opts)}
    end
  end

  defp web_uri(repo_url) do
    case URI.new(repo_url) do
      {:ok, %URI{scheme: scheme, host: host} = uri}
      when scheme in ["https", "http"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _not_a_web_url ->
        {:error, :invalid_url}
    end
  end

  # Every address the host answers with must be public — the same rule the
  # save-time validation applies, asked again here. The one we return is the
  # one dialled, so what was checked is what is connected to.
  defp public_address(host) do
    case resolve(host) do
      [] ->
        {:error, :unresolvable}

      addresses ->
        if Enum.any?(addresses, &PrivateAddress.private_address?/1),
          do: {:error, :private_address},
          else: {:ok, hd(addresses)}
    end
  end

  defp resolve(host) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, address} -> [address]
      {:error, _not_a_literal} -> getaddrs(charlist, :inet) ++ getaddrs(charlist, :inet6)
    end
  end

  # Indirected so tests can name what a host resolves to without a real
  # lookup — the interesting cases here are a name answering with a private
  # address, and one whose answer changes between two calls.
  defp getaddrs(charlist, family) do
    resolver = Application.get_env(:varsel, :dns_resolver, :inet)

    case resolver.getaddrs(charlist, family) do
      {:ok, addresses} -> addresses
      {:error, _unresolvable} -> []
    end
  end

  defp transport(uri, address, opts) do
    opts = Keyword.put(opts, :connect_options, pin_to(uri.host))
    Transport.HTTP.new(pinned_url(uri, address), opts)
  end

  # The address takes the host's place in the URL. `URI.to_string/1` brackets
  # an IPv6 host itself, so it is stored bare.
  defp pinned_url(uri, address) do
    URI.to_string(%{uri | host: address |> :inet.ntoa() |> to_string()})
  end

  # Mint dials the URL's host but takes every *name* from `:hostname` — the
  # `Host` header, the TLS server name, and the name the certificate is
  # checked against. Setting it back to the real host is what makes an
  # address-pinned request still look and verify like a request to the name:
  # a forge serving many repos still routes it, and pinning cannot be used to
  # slip past certificate verification.
  # On an `http` URL exgit adds no TLS options, so `transport_opts` is inert
  # and only the `Host` header part applies.
  defp pin_to(host) do
    [
      hostname: host,
      transport_opts: [
        customize_hostname_check: [
          match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
        ]
      ]
    ]
  end
end
