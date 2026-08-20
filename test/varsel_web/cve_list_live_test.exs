# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveListLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Varsel.CVE.CveRecord

  defp published(cve_id, title, metrics \\ [], date_published \\ "2025-06-16T11:00:00.000Z") do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "state" => "PUBLISHED",
        "datePublished" => date_published,
        "dateUpdated" => "2025-06-17T12:00:00.000Z"
      },
      "containers" => %{
        "cna" => %{
          "title" => title,
          "descriptions" => [%{"lang" => "en", "value" => "#{title} description."}],
          "affected" => [%{"packageURL" => "pkg:hex/#{String.downcase(title)}"}],
          "references" => [],
          "metrics" => metrics
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  test "lists published CVEs", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")
    published("CVE-2025-0002", "Bravo")

    {:ok, _lv, html} = live(conn, ~p"/cves")

    assert html =~ "CVE-2025-0001"
    assert html =~ "Alpha"
    assert html =~ "CVE-2025-0002"
  end

  test "the card's toolbar carries the count and the feeds", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")
    published("CVE-2025-0002", "Bravo")

    {:ok, lv, html} = live(conn, ~p"/cves")

    assert html =~ "2 CVEs"
    assert has_element?(lv, ~s{p a[href="/cves/index.json"]}, "JSON")
    assert has_element?(lv, ~s{p a[href="/osv/all.json"]}, "OSV")
    assert has_element?(lv, ~s{p a[href="/feed.atom"]}, "Atom")
    assert has_element?(lv, ~s{p a[href="/feed.rss"]}, "RSS")
    # The floating feeds paragraph below the card is gone (the site footer
    # keeps its own copy of the links).
    refute has_element?(lv, "p.mt-6", "Machine-readable")
  end

  test "rows click through to the public detail page", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")

    {:ok, lv, _html} = live(conn, ~p"/cves")

    # /cves/:cve_id is a controller page, so the JS.navigate click-through
    # surfaces as a redirect out of the LiveView.
    {:error, {_kind, %{to: to}}} =
      lv
      |> element("tbody tr[phx-click]")
      |> render_click()

    assert to == "/cves/CVE-2025-0001.html"
  end

  test "live search narrows the results", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")
    published("CVE-2025-0002", "Bravo")

    {:ok, lv, _html} = live(conn, ~p"/cves")

    html = lv |> form("#cve-record-search", %{query: "Alpha"}) |> render_change()

    assert html =~ "Alpha"
    refute html =~ "Bravo"
  end

  test "shows an empty state when nothing matches", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")

    {:ok, lv, _html} = live(conn, ~p"/cves")
    html = lv |> form("#cve-record-search", %{query: "zzzznotfound"}) |> render_change()

    assert html =~ "No CVEs match"
  end

  describe "URL pagination" do
    # 30 published records, dated so the sort (date_published desc) is
    # deterministic: CVE-2025-1030 is newest and leads page one,
    # CVE-2025-1005..1001 land on page two (limit 25).
    defp thirty_published do
      for i <- 1..30 do
        id = "CVE-2025-#{String.pad_leading(to_string(1000 + i), 4, "0")}"
        date = "#{Date.add(~D[2025-01-01], i)}T11:00:00.000Z"
        published(id, "title#{i}", [], date)
      end
    end

    defp detail_link(id), do: ~s{a[href="/cves/#{id}.html"]}

    # The pager form scopes the selector — the nav also links /cves.
    @pager ~s{form[phx-submit="jump_page"]}

    test "the dead render serves any page by offset, with real anchors", %{conn: conn} do
      thirty_published()

      html = conn |> get("/cves?offset=25") |> html_response(200)
      document = LazyHTML.from_document(html)

      assert document |> LazyHTML.query(detail_link("CVE-2025-1005")) |> Enum.count() == 1
      assert document |> LazyHTML.query(detail_link("CVE-2025-1030")) |> Enum.count() == 0
      assert document |> LazyHTML.query(~s{#{@pager} a[href="/cves"]}) |> Enum.count() == 1
    end

    test "the pager's next link patches to the next offset", %{conn: conn} do
      thirty_published()

      {:ok, lv, _html} = live(conn, ~p"/cves")

      assert has_element?(lv, detail_link("CVE-2025-1030"))
      refute has_element?(lv, detail_link("CVE-2025-1005"))

      lv |> element("#{@pager} a", "»") |> render_click()
      assert_patch(lv, "/cves?offset=25")

      assert has_element?(lv, detail_link("CVE-2025-1005"))
      refute has_element?(lv, detail_link("CVE-2025-1030"))

      lv |> element("#{@pager} a", "«") |> render_click()
      assert_patch(lv, "/cves")

      assert has_element?(lv, detail_link("CVE-2025-1030"))
    end

    test "jump-to-page round-trips through the URL", %{conn: conn} do
      thirty_published()

      {:ok, lv, _html} = live(conn, ~p"/cves")

      lv |> form(@pager, %{page: "2"}) |> render_submit()
      assert_patch(lv, "/cves?offset=25")

      assert has_element?(lv, detail_link("CVE-2025-1001"))
    end

    test "searching resets to the first page", %{conn: conn} do
      thirty_published()

      {:ok, lv, _html} = live(conn, ~p"/cves?offset=25")

      lv |> form("#cve-record-search", %{query: "title30"}) |> render_change()
      assert_patch(lv, "/cves")

      assert has_element?(lv, detail_link("CVE-2025-1030"))
    end

    test "a malformed offset falls back to the first page", %{conn: conn} do
      thirty_published()

      for bad <- ["abc", "-25", "1e2"] do
        {:ok, lv, _html} = live(conn, "/cves?offset=#{bad}")
        assert has_element?(lv, detail_link("CVE-2025-1030"))
      end
    end
  end

  test "renders a compact severity chip, dashed when unscored", %{conn: conn} do
    published("CVE-2025-0001", "Alpha", [
      %{
        "cvssV3_1" => %{
          "baseScore" => 2.6,
          "vectorString" => "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N"
        }
      }
    ])

    published("CVE-2025-0002", "Bravo")

    {:ok, _lv, html} = live(conn, ~p"/cves")

    assert html =~ "L 2.6"
    assert html =~ "no score"
  end
end
