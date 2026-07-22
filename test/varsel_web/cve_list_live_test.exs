# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveListLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Varsel.CVE.CveRecord

  defp published(cve_id, title, metrics \\ []) do
    cve_json = %{
      "dataType" => "CVE_RECORD",
      "dataVersion" => "5.2",
      "cveMetadata" => %{
        "cveId" => cve_id,
        "state" => "PUBLISHED",
        "datePublished" => "2025-06-16T11:00:00.000Z",
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

    assert to == "/cves/CVE-2025-0001"
  end

  test "live search narrows the results", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")
    published("CVE-2025-0002", "Bravo")

    {:ok, lv, _html} = live(conn, ~p"/cves")

    html = lv |> form("form", %{query: "Alpha"}) |> render_change()

    assert html =~ "Alpha"
    refute html =~ "Bravo"
  end

  test "shows an empty state when nothing matches", %{conn: conn} do
    published("CVE-2025-0001", "Alpha")

    {:ok, lv, _html} = live(conn, ~p"/cves")
    html = lv |> form("form", %{query: "zzzznotfound"}) |> render_change()

    assert html =~ "No CVEs match"
  end

  test "renders a compact severity chip, dashed when unscored", %{conn: conn} do
    published("CVE-2025-0001", "Alpha", [
      %{"cvssV3_1" => %{"baseScore" => 7.5, "vectorString" => "CVSS:3.1/AV:N"}}
    ])

    published("CVE-2025-0002", "Bravo")

    {:ok, _lv, html} = live(conn, ~p"/cves")

    assert html =~ "H 7.5"
    assert html =~ "no score"
  end
end
