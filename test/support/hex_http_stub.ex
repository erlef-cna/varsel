# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Test.HexHTTPStub do
  @moduledoc """
  `:hex_http` adapter stub for tests.

  Reports a package as existing when its name is in the
  `:hex_stub_packages` application env, which is either a list of names
  (packages without releases) or a map of name to released versions:

      Application.put_env(:cve_management, :hex_stub_packages, ["plug"])
      Application.put_env(:cve_management, :hex_stub_packages, %{"plug" => ["1.0.0", "1.1.0"]})
  """

  @behaviour :hex_http

  @impl :hex_http
  def request(:get, url, _headers, _body, _adapter_config) do
    name = url |> to_string() |> URI.parse() |> Map.fetch!(:path) |> Path.basename()

    case stubbed_versions(name) do
      {:ok, versions} ->
        body =
          :erlang.term_to_binary(%{
            "name" => name,
            "releases" => Enum.map(versions, &%{"version" => &1})
          })

        {:ok, {200, %{"content-type" => "application/vnd.hex+erlang"}, body}}

      :error ->
        {:ok, {404, %{"content-type" => "application/vnd.hex+erlang"}, :erlang.term_to_binary(%{})}}
    end
  end

  @impl :hex_http
  def request_to_file(_method, _url, _headers, _body, _filename, _adapter_config) do
    {:error, :not_supported}
  end

  defp stubbed_versions(name) do
    case Application.get_env(:cve_management, :hex_stub_packages, []) do
      %{} = packages -> Map.fetch(packages, name)
      packages when is_list(packages) -> if name in packages, do: {:ok, []}, else: :error
    end
  end
end
