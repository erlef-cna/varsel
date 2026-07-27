# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.FeedControllerTest do
  use VarselWeb.ConnCase, async: false

  alias Varsel.CVE.CveRecord

  @cve_id "CVE-2025-12345"

  # Every XML metacharacter, plus the shapes that would break out of a text
  # node or an attribute if anything were concatenated instead of encoded.
  @hostile ~S|A & B <script>alert(1)</script> "quoted" 'single' ]]> </title>|

  defp publish(opts \\ []) do
    title = Keyword.get(opts, :title, "Test vulnerability")
    description = Keyword.get(opts, :description, "A test vulnerability.")

    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => @cve_id,
        "state" => "PUBLISHED",
        "datePublished" => "2025-06-16T11:00:00.000Z",
        "dateUpdated" => "2025-06-17T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "title" => title,
          "descriptions" => [%{"lang" => "en", "value" => description}],
          "affected" => [],
          "references" => []
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  describe "GET /feed.atom" do
    test "returns a valid atom feed with the right content type", %{conn: conn} do
      publish()

      conn = get(conn, ~p"/feed.atom")

      assert conn |> get_resp_header("content-type") |> hd() =~ "application/atom+xml"
      body = response(conn, 200)
      assert body =~ "<feed xmlns=\"http://www.w3.org/2005/Atom\">"
      assert body =~ @cve_id
      assert body =~ "Test vulnerability"
      assert body =~ "/cves/#{@cve_id}.html"
    end
  end

  describe "GET /feed.rss" do
    test "returns a valid rss feed with the right content type", %{conn: conn} do
      publish()

      conn = get(conn, ~p"/feed.rss")

      assert conn |> get_resp_header("content-type") |> hd() =~ "application/rss+xml"
      body = response(conn, 200)
      assert body =~ "<rss version=\"2.0\""
      assert body =~ @cve_id
    end
  end

  # The feeds are built as XML and encoded, so a value that looks like markup
  # has to survive as *text* — parseable, and identical to what went in.
  describe "hostile content" do
    for {name, path} <- [atom: "/feed.atom", rss: "/feed.rss"] do
      test "#{name}: a title full of markup stays text", %{conn: conn} do
        publish(title: @hostile)

        body = conn |> get(unquote(path)) |> response(200)

        assert {:ok, texts} = text_nodes(body)
        assert Enum.any?(texts, &String.contains?(&1, @hostile))

        # The dangerous shapes only ever appear escaped in the document.
        refute body =~ "<script>"
        refute body =~ "]]>"
      end

      test "#{name}: a description full of markup stays text", %{conn: conn} do
        publish(description: @hostile)

        body = conn |> get(unquote(path)) |> response(200)

        assert {:ok, texts} = text_nodes(body)
        assert Enum.any?(texts, &String.contains?(&1, @hostile))
        refute body =~ "<script>"
      end
    end

    test "a spoofed Host cannot inject markup into the feed", %{conn: conn} do
      publish()

      body =
        %{conn | host: ~S|evil.example"><script>alert(1)</script>|}
        |> get(~p"/feed.atom")
        |> response(200)

      assert {:ok, _texts} = text_nodes(body)
      refute body =~ "<script>"
    end
  end

  # Parses the document and returns every text node, which doubles as a
  # well-formedness check: malformed XML fails here rather than in a browser.
  defp text_nodes(xml) do
    with {:ok, tree} <- Saxy.SimpleForm.parse_string(xml) do
      {:ok, collect_text(tree)}
    end
  end

  defp collect_text({_name, _attrs, children}), do: Enum.flat_map(children, &collect_text/1)
  defp collect_text(text) when is_binary(text), do: [text]
end
