# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.Plugs.ReturnPathTest do
  use ExUnit.Case, async: true

  alias VarselWeb.Plugs.ReturnPath

  describe "safe_path/1 accepts a path on this site" do
    test "a plain path" do
      assert ReturnPath.safe_path("/report") == {:ok, "/report"}
    end

    test "a nested path" do
      assert ReturnPath.safe_path("/cases/123/edit") == {:ok, "/cases/123/edit"}
    end

    test "keeps the query string and fragment of the page returned to" do
      assert ReturnPath.safe_path("/cases?filter=open") == {:ok, "/cases?filter=open"}
      assert ReturnPath.safe_path("/cves#weaknesses") == {:ok, "/cves#weaknesses"}
    end

    # The home page is the safest target there is; a visitor signing in from
    # the nav while already on it has nowhere more specific to come back to.
    test "the root path" do
      assert ReturnPath.safe_path("/") == {:ok, "/"}
    end
  end

  describe "safe_path/1 refuses anything that could leave the site" do
    # Each of these would turn the sign-in link into an open redirect.
    test "an absolute URL" do
      assert ReturnPath.safe_path("https://evil.com") == :error
      assert ReturnPath.safe_path("http://evil.com/report") == :error
    end

    test "a non-http scheme" do
      assert ReturnPath.safe_path("javascript:alert(1)") == :error
      assert ReturnPath.safe_path("data:text/html,x") == :error
    end

    # The case a bare starts_with?("/") check lets through: a browser reads
    # this as a host, not as a path here.
    test "a protocol-relative URL" do
      assert ReturnPath.safe_path("//evil.com") == :error
      assert ReturnPath.safe_path("//evil.com/report") == :error
    end

    test "backslash and encoded spellings of the same trick" do
      assert ReturnPath.safe_path("/\\evil.com") == :error
      assert ReturnPath.safe_path("/%2fevil.com") == :error
      assert ReturnPath.safe_path("/%5cevil.com") == :error
    end

    test "a bare path with no leading slash" do
      assert ReturnPath.safe_path("report") == :error
      assert ReturnPath.safe_path("evil.com") == :error
    end

    test "empty input" do
      assert ReturnPath.safe_path("") == :error
    end

    test "a control character that has no business in a Location header" do
      assert ReturnPath.safe_path("/report\nX") == :error
      assert ReturnPath.safe_path("/report\r\nSet-Cookie: x=1") == :error
    end
  end

  # An accepted path is returned exactly as it came in. The guard asserts the
  # input is already canonical rather than rewriting it into something the
  # caller never asked for.
  describe "safe_path/1 never rewrites what it accepts" do
    test "returns the input verbatim, query and fragment intact" do
      for path <- ["/", "/report", "/cases?filter=open", "/cves#weaknesses", "/a/b/c"] do
        assert ReturnPath.safe_path(path) == {:ok, path}
      end
    end
  end

  # Two checks guard this, and neither is redundant — deleting either one
  # reopens a hole the other does not cover.
  describe "the round-trip check and the character check each catch what the other misses" do
    test "the round-trip alone would admit the encoded spellings" do
      # URI parses these as ordinary local paths and they round-trip
      # unchanged, but a proxy that decodes %2f first hands the browser
      # "//evil.com".
      assert {:ok, %URI{scheme: nil, host: nil}} = URI.new("/%2fevil.com")
      assert ReturnPath.safe_path("/%2fevil.com") == :error
      assert ReturnPath.safe_path("/%5cevil.com") == :error
    end

    test "the round-trip alone would admit a bare relative path" do
      # No leading slash, so the browser resolves it against the current
      # directory rather than the site root.
      assert {:ok, %URI{scheme: nil, host: nil}} = URI.new("evil.com")
      assert ReturnPath.safe_path("evil.com") == :error
    end

    test "the character check alone would admit anything URI refuses to parse" do
      # A backslash, a raw newline and a space never survive URI.new/1, so
      # they are stopped before the character check ever sees them.
      assert {:error, _at} = URI.new("/\\evil.com")
      assert ReturnPath.safe_path("/\\evil.com") == :error
      assert ReturnPath.safe_path("/report\nX") == :error
    end
  end
end
