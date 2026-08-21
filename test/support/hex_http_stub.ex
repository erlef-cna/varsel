# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Test.HexHTTPStub do
  @moduledoc """
  `:hex_http` adapter stub for tests.

  Serves the registry's `packages/<name>` resource as an unsigned protobuf
  (the test config turns signature checks off) for every name in the
  `:hex_stub_packages` application env, which is either a list of names
  (packages without releases) or a map of name to released versions:

      Application.put_env(:varsel, :hex_stub_packages, ["plug"])
      Application.put_env(:varsel, :hex_stub_packages, %{"plug" => ["1.0.0", "1.1.0"]})

  Users are stubbed the same way through `:hex_stub_users`, a list of
  usernames. hex.pm lowercases handles, so a lookup matches case-insensitively
  and answers with the stored spelling:

      Application.put_env(:varsel, :hex_stub_users, ["alice"])
  """

  @behaviour :hex_http

  @impl :hex_http
  def request(:get, url, _headers, _body, _adapter_config) do
    path = url |> to_string() |> URI.parse() |> Map.fetch!(:path)
    name = Path.basename(path)

    if String.contains?(path, "/users/") do
      user_response(name)
    else
      package_response(name)
    end
  end

  @impl :hex_http
  def request_to_file(_method, _url, _headers, _body, _filename, _adapter_config) do
    {:error, :not_supported}
  end

  defp package_response(name) do
    case stubbed_versions(name) do
      {:ok, versions} ->
        package = %{
          repository: "hexpm",
          name: name,
          releases: Enum.map(versions, &%{version: &1, inner_checksum: <<>>, dependencies: []})
        }

        signed =
          :hex_pb_signed.encode_msg(
            %{payload: :hex_registry.encode_package(package), signature: <<>>},
            :Signed
          )

        {:ok, {200, %{}, :zlib.gzip(signed)}}

      :error ->
        not_found()
    end
  end

  defp user_response(name) do
    :varsel
    |> Application.get_env(:hex_stub_users, [])
    |> Enum.find(&(String.downcase(&1) == String.downcase(name)))
    |> case do
      nil -> not_found()
      username -> ok(%{"username" => username})
    end
  end

  defp ok(body) do
    {:ok, {200, %{"content-type" => "application/vnd.hex+erlang"}, :erlang.term_to_binary(body)}}
  end

  defp not_found do
    {:ok, {404, %{"content-type" => "application/vnd.hex+erlang"}, :erlang.term_to_binary(%{})}}
  end

  defp stubbed_versions(name) do
    case Application.get_env(:varsel, :hex_stub_packages, []) do
      %{} = packages -> Map.fetch(packages, name)
      packages when is_list(packages) -> if name in packages, do: {:ok, []}, else: :error
    end
  end
end
