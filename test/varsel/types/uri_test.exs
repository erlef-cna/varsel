# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.Types.URITest do
  use ExUnit.Case, async: true

  alias Varsel.Types.URI, as: Type

  defp cast(value, constraints \\ []) do
    with {:ok, cast} <- Ash.Type.cast_input(Type, value, constraints) do
      Ash.Type.apply_constraints(Type, cast, constraints)
    end
  end

  describe "normalization" do
    test "the scheme and host are lowercased" do
      assert {:ok, "https://example.com/Path"} = cast("HTTPS://Example.COM/Path")
    end

    test "the path keeps its casing — only the authority is case-insensitive" do
      assert {:ok, "https://example.com/AcMe/LiB"} = cast("https://example.com/AcMe/LiB")
    end

    test "userinfo, port and query survive" do
      assert {:ok, "https://u:p@example.com:8443/x?a=1"} =
               cast("HTTPS://u:p@Example.com:8443/x?a=1")
    end

    test "a %URI{} casts to its string form" do
      assert {:ok, "https://example.com/x"} = cast(URI.parse("https://example.com/x"))
    end

    test "nil passes through" do
      assert {:ok, nil} = cast(nil)
    end

    test "a non-string is refused" do
      assert {:error, _} = cast(123)
    end
  end

  describe "schemes constraint" do
    test "accepts a listed scheme, however it was spelled" do
      assert {:ok, "https://example.com/x"} = cast("HTTPS://example.com/x", schemes: ["https"])
    end

    test "refuses an unlisted scheme" do
      for url <- ["http://example.com/x", "file:///etc/passwd", "ftp://example.com/x"] do
        assert {:error, _} = cast(url, schemes: ["https"]), "expected #{url} refused"
      end
    end

    test "accepts any scheme when unconstrained" do
      assert {:ok, "ftp://example.com/x"} = cast("ftp://example.com/x")
    end

    test "the message names the accepted schemes" do
      assert {:error, [message: message]} = cast("ftp://example.com/x", schemes: ["https"])
      assert message =~ "https"
    end
  end

  describe "absolute constraint" do
    test "refuses a URL missing a scheme or a host" do
      for url <- [
            "https:///x",
            "/just/a/path",
            "mailto:a@example.com",
            # Has a host but no scheme — the case a host-only check misses.
            "//example.com/x"
          ] do
        assert {:error, _} = cast(url, absolute: true), "expected #{url} refused"
      end
    end

    test "accepts a URL with both" do
      assert {:ok, "https://example.com/x"} = cast("https://example.com/x", absolute: true)
    end

    test "allows a relative URL by default" do
      assert {:ok, "/just/a/path"} = cast("/just/a/path")
      assert {:ok, "//example.com/x"} = cast("//example.com/x")
    end
  end

  describe "public_host constraint" do
    # IP literals resolve to themselves, so these need no DNS.
    test "refuses a private address literal" do
      for url <- [
            "https://127.0.0.1/x",
            "https://10.0.0.1/x",
            "https://192.168.1.1/x",
            "https://169.254.169.254/x",
            "https://[::1]/x"
          ] do
        assert {:error, _} = cast(url, public_host: true), "expected #{url} refused"
      end
    end

    test "accepts a public address literal" do
      assert {:ok, "https://93.184.216.34/x"} = cast("https://93.184.216.34/x", public_host: true)
    end

    test "is not applied when unconstrained" do
      assert {:ok, "https://127.0.0.1/x"} = cast("https://127.0.0.1/x")
    end
  end

  describe "storage" do
    test "round-trips as a plain string" do
      assert {:ok, "https://example.com/x"} =
               Ash.Type.dump_to_native(Type, "https://example.com/x", [])

      assert {:ok, "https://example.com/x"} =
               Ash.Type.cast_stored(Type, "https://example.com/x", [])
    end
  end
end
