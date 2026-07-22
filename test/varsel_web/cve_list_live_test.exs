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
