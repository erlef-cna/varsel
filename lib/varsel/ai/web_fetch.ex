# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI.WebFetch do
  @moduledoc """
  Fetches public web pages (advisories, changelogs, commits) for the AI
  research tools.

  Internal only — deliberately never exposed as an MCP/GraphQL tool: a
  server-side fetcher callable by outside users would be an open proxy and
  SSRF primitive. As a second layer, requests to loopback/private/link-local
  hosts are rejected outright.

  HTML responses are reduced to plain text and long bodies are truncated to
  keep tool results within a sane token budget. Extra Req options (e.g. a
  `Req.Test` plug) merge in via `config :varsel, :web_fetch`; with a plug
  configured no real connection happens, so the DNS-based address check is
  skipped.
  """

  @max_chars 30_000
  @blocked_suffixes [".localhost", ".local", ".internal"]

  @doc "Fetches a public http(s) URL, returning status/content-type/text body."
  @spec fetch(String.t()) :: {:ok, map()} | {:error, String.t()}
  def fetch(url) when is_binary(url) do
    with {:ok, uri} <- parse(url),
         :ok <- guard_host(uri.host) do
      request(url)
    end
  end

  ## ---------------------------------------------------------- target checks

  defp parse(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host} = uri}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        {:ok, uri}

      _other ->
        {:error, "only absolute http(s) URLs can be fetched"}
    end
  end

  defp guard_host(host) do
    internal? =
      host == "localhost" or String.ends_with?(host, @blocked_suffixes) or
        internal_address?(host)

    if internal? do
      {:error, "#{host} is not a public host"}
    else
      :ok
    end
  end

  defp internal_address?(host) do
    case :inet.parse_address(String.to_charlist(host)) do
      {:ok, address} -> reserved?(address)
      {:error, _not_an_ip_literal} -> resolves_to_reserved?(host)
    end
  end

  defp resolves_to_reserved?(host) do
    if req_options()[:plug] do
      false
    else
      case :inet.getaddr(String.to_charlist(host), :inet) do
        {:ok, address} -> reserved?(address)
        # Unresolvable names fail at connect time with a clearer error.
        {:error, _reason} -> false
      end
    end
  end

  # RFC1918/loopback/link-local/CGNAT/unspecified v4; loopback/ULA/link-local v6.
  defp reserved?({0, _b, _c, _d}), do: true
  defp reserved?({10, _b, _c, _d}), do: true
  defp reserved?({100, b, _c, _d}) when b in 64..127, do: true
  defp reserved?({127, _b, _c, _d}), do: true
  defp reserved?({169, 254, _c, _d}), do: true
  defp reserved?({172, b, _c, _d}) when b in 16..31, do: true
  defp reserved?({192, 168, _c, _d}), do: true

  # IPv4-mapped IPv6 (::ffff:a.b.c.d) re-checks as v4.
  defp reserved?({0, 0, 0, 0, 0, 0xFFFF, hi, lo}) do
    reserved?({div(hi, 256), rem(hi, 256), div(lo, 256), rem(lo, 256)})
  end

  defp reserved?({0, 0, 0, 0, 0, 0, 0, 1}), do: true

  defp reserved?(address) when tuple_size(address) == 8 do
    elem(address, 0) in 0xFC00..0xFDFF or elem(address, 0) in 0xFE80..0xFEBF
  end

  defp reserved?(_address), do: false

  ## ---------------------------------------------------------------- request

  defp request(url) do
    [
      url: url,
      redirect: true,
      max_redirects: 3,
      receive_timeout: to_timeout(second: 15),
      retry: false
    ]
    |> Req.request(req_options())
    |> case do
      {:ok, %Req.Response{} = response} -> {:ok, summarize(response)}
      {:error, exception} -> {:error, "fetch failed: #{Exception.message(exception)}"}
    end
  end

  defp req_options, do: Application.get_env(:varsel, :web_fetch, [])

  defp summarize(response) do
    content_type = response |> Req.Response.get_header("content-type") |> List.first() || ""
    text = response.body |> body_text(content_type) |> String.trim()
    truncated? = String.length(text) > @max_chars

    %{
      "status" => response.status,
      "content_type" => content_type,
      "body" => String.slice(text, 0, @max_chars),
      "truncated" => truncated?
    }
  end

  ## --------------------------------------------------------- body handling

  # Req decodes JSON bodies to maps/lists; re-encode those readably.
  defp body_text(body, _content_type) when is_map(body) or is_list(body) do
    Jason.encode!(body, pretty: true)
  end

  defp body_text(body, content_type) when is_binary(body) do
    cond do
      String.starts_with?(content_type, "text/html") -> html_to_text(body)
      String.valid?(body) -> body
      true -> "(binary response, #{byte_size(body)} bytes)"
    end
  end

  defp body_text(body, _content_type), do: inspect(body)

  defp html_to_text(html) do
    html
    |> String.replace(~r/<(script|style)[^>]*>.*?<\/\1>/is, " ")
    |> String.replace(~r/<!--.*?-->/s, " ")
    |> String.replace(
      ~r{</?(p|div|section|article|li|tr|table|h[1-6]|br|ul|ol|blockquote|pre)[^>]*>}i,
      "\n"
    )
    |> String.replace(~r/<[^>]*>/, " ")
    |> decode_entities()
    |> String.replace(~r/[ \t]+/, " ")
    |> String.replace(~r/\s*\n\s*(\n\s*)+/, "\n\n")
  end

  # The handful of entities that matter for readability; &amp; comes last so
  # double-encoded input does not decode twice.
  defp decode_entities(text) do
    text
    |> String.replace("&nbsp;", " ")
    |> String.replace("&lt;", "<")
    |> String.replace("&gt;", ">")
    |> String.replace("&quot;", "\"")
    |> String.replace(["&#39;", "&apos;"], "'")
    |> String.replace("&amp;", "&")
  end
end
