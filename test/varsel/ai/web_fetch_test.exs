# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule Varsel.AI.WebFetchTest do
  use ExUnit.Case, async: true

  alias Varsel.AI.WebFetch

  describe "target validation" do
    test "rejects non-http(s) and relative URLs" do
      assert {:error, message} = WebFetch.fetch("ftp://example.com/file")
      assert message =~ "http(s)"

      assert {:error, _message} = WebFetch.fetch("file:///etc/passwd")
      assert {:error, _message} = WebFetch.fetch("/relative/path")
      assert {:error, _message} = WebFetch.fetch("not a url")
    end

    test "rejects loopback, private, and internal hosts" do
      for url <- [
            "http://localhost/admin",
            "http://127.0.0.1:4000/",
            "http://[::1]/",
            "http://10.1.2.3/",
            "http://172.16.0.1/",
            "http://192.168.1.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.0.1/",
            "https://foo.internal/",
            "https://printer.local/"
          ] do
        assert {:error, message} = WebFetch.fetch(url), "expected #{url} to be rejected"
        assert message =~ "not a public host"
      end
    end
  end

  describe "fetching" do
    test "reduces HTML to text" do
      Req.Test.stub(WebFetch, fn conn ->
        conn
        |> Plug.Conn.put_resp_content_type("text/html")
        |> Plug.Conn.send_resp(200, """
        <html><head><title>Advisory</title><style>.x{color:red}</style>
        <script>evil()</script></head>
        <body><h1>CVE in acme_lib</h1><p>Affects &lt;= 1.2.3 &amp; earlier.</p></body></html>
        """)
      end)

      assert {:ok, result} = WebFetch.fetch("https://example.com/advisory")
      assert result["status"] == 200
      assert result["body"] =~ "CVE in acme_lib"
      assert result["body"] =~ "Affects <= 1.2.3 & earlier."
      refute result["body"] =~ "evil()"
      refute result["body"] =~ "color:red"
      refute result["truncated"]
    end

    test "re-encodes decoded JSON bodies readably" do
      Req.Test.stub(WebFetch, fn conn ->
        Req.Test.json(conn, %{"name" => "acme_lib", "latest" => "1.2.4"})
      end)

      assert {:ok, result} = WebFetch.fetch("https://example.com/api.json")
      assert result["body"] =~ ~s("name": "acme_lib")
    end

    test "truncates long bodies" do
      Req.Test.stub(WebFetch, fn conn ->
        Plug.Conn.send_resp(conn, 200, String.duplicate("a", 40_000))
      end)

      assert {:ok, result} = WebFetch.fetch("https://example.com/big")
      assert result["truncated"]
      assert String.length(result["body"]) == 30_000
    end

    test "returns non-200 responses with their status" do
      Req.Test.stub(WebFetch, fn conn ->
        Plug.Conn.send_resp(conn, 404, "gone")
      end)

      assert {:ok, %{"status" => 404, "body" => "gone"}} =
               WebFetch.fetch("https://example.com/missing")
    end
  end
end
