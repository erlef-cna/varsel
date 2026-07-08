# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagement.Test.HexHTTPStub do
  @moduledoc """
  `:hex_http` adapter stub for tests.

  Reports a package as existing when its name is in the
  `:hex_stub_packages` application env list:

      Application.put_env(:cve_management, :hex_stub_packages, ["plug"])
  """

  @behaviour :hex_http

  @impl :hex_http
  def request(:get, url, _headers, _body, _adapter_config) do
    name = url |> to_string() |> URI.parse() |> Map.fetch!(:path) |> Path.basename()

    if name in Application.get_env(:cve_management, :hex_stub_packages, []) do
      body = :erlang.term_to_binary(%{"name" => name})
      {:ok, {200, %{"content-type" => "application/vnd.hex+erlang"}, body}}
    else
      {:ok, {404, %{"content-type" => "application/vnd.hex+erlang"}, :erlang.term_to_binary(%{})}}
    end
  end

  @impl :hex_http
  def request_to_file(_method, _url, _headers, _body, _filename, _adapter_config) do
    {:error, :not_supported}
  end
end
