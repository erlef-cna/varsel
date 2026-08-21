# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.HexPmTest do
  use ExUnit.Case, async: false

  alias Varsel.HexPm

  defmodule UrlSpy do
    @moduledoc false
    @behaviour :hex_http

    @impl :hex_http
    def request(_method, url, _headers, _body, %{test: test}) do
      send(test, {:requested, to_string(url)})
      {:ok, {404, %{}, ""}}
    end

    @impl :hex_http
    def request_to_file(_method, _url, _headers, _body, _filename, _adapter_config) do
      {:error, :not_supported}
    end
  end

  setup do
    original = Application.get_env(:varsel, :hex_core)
    Application.put_env(:varsel, :hex_core, %{http_adapter: {UrlSpy, %{test: self()}}})

    on_exit(fn ->
      Application.put_env(:varsel, :hex_core, original)
      Application.delete_env(:varsel, :hex)
    end)

    :ok
  end

  test "asks the instance sign-in uses" do
    Application.put_env(:varsel, :hex, base_url: "http://localhost:4000")

    HexPm.user("alice")

    assert_received {:requested, "http://localhost:4000/api/users/alice"}
  end

  test "falls back to the public API when no instance is configured" do
    Application.delete_env(:varsel, :hex)

    HexPm.user("alice")

    assert_received {:requested, "https://hex.pm/api/users/alice"}
  end

  test "package lookups read hex.pm's registry for hex.pm" do
    Application.put_env(:varsel, :hex, base_url: "https://hex.pm")

    HexPm.package_exists?("plug")

    assert_received {:requested, "https://repo.hex.pm/packages/plug"}
  end

  test "package lookups read staging's registry for staging" do
    Application.put_env(:varsel, :hex, base_url: "https://staging.hex.pm")

    HexPm.package_exists?("plug")

    assert_received {:requested, "https://repo.staging.hex.pm/packages/plug"}
  end

  test "package lookups read a local hexpm's registry under /repo" do
    Application.put_env(:varsel, :hex, base_url: "http://localhost:4000")

    HexPm.package_versions("plug")

    assert_received {:requested, "http://localhost:4000/repo/packages/plug"}
  end
end
