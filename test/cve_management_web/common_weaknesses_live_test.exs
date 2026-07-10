# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule CveManagementWeb.CommonWeaknessesLiveTest do
  use CveManagementWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias CveManagement.CVE.CveRecord
  alias CveManagement.CWE.Weakness
  alias CveManagement.CWE.WeaknessRelationship

  # A tiny CWE tree: 707 (class) -> 74 (class) -> 79 (base).
  defp seed_cwe_tree do
    for {id, name, abstraction} <- [
          {707, "Improper Neutralization", :class},
          {74, "Injection", :class},
          {79, "Cross-site Scripting", :base}
        ] do
      Ash.create!(
        Weakness,
        %{cwe_id: id, name: name, abstraction: abstraction, status: :stable, description: name},
        action: :upsert,
        authorize?: false
      )
    end

    for {source, target} <- [{79, 74}, {74, 707}] do
      Ash.create!(
        WeaknessRelationship,
        %{source_cwe_id: source, target_cwe_id: target, nature: :child_of, view_id: 1000},
        authorize?: false
      )
    end
  end

  defp publish_cve(cve_id, cwe_id) do
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
          "title" => "#{cve_id} vulnerability",
          "descriptions" => [%{"lang" => "en", "value" => "A vulnerability."}],
          "affected" => [%{"packageURL" => "pkg:hex/demo"}],
          "problemTypes" => [
            %{"descriptions" => [%{"cweId" => "CWE-#{cwe_id}", "lang" => "en", "type" => "CWE"}]}
          ],
          "references" => []
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  setup do
    seed_cwe_tree()
    publish_cve("CVE-2025-0001", 79)
    publish_cve("CVE-2025-0002", 79)
    :ok
  end

  test "renders the donut at the top level", %{conn: conn} do
    {:ok, _lv, html} = live(conn, ~p"/common-weaknesses")

    assert html =~ "Common Weaknesses"
    assert html =~ "<svg"
    # CWE-79 rolls up to its chain root CWE-707 at the top level.
    assert html =~ "Improper Neutralization"
    assert html =~ "CWE-707"
  end

  test "clicking a slice drills down and updates the URL", %{conn: conn} do
    {:ok, lv, _html} = live(conn, ~p"/common-weaknesses")

    lv
    |> element(~s([phx-value-cwe="CWE-707"][phx-value-drill="true"]))
    |> render_click()

    assert_patched(lv, ~p"/common-weaknesses?focus=CWE-707")
    html = render(lv)
    # Drilled into 707 -> shows its child CWE-74.
    assert html =~ "CWE-74"
    assert html =~ "All classes"
  end

  test "a direct focus URL renders the drilled level", %{conn: conn} do
    {:ok, _lv, html} = live(conn, ~p"/common-weaknesses?focus=CWE-707")

    assert html =~ "CWE-74"
    assert html =~ "All classes"
  end

  test "clicking a legend row shows the filtered CVE list", %{conn: conn} do
    {:ok, lv, _html} = live(conn, ~p"/common-weaknesses")

    html =
      lv
      |> element(~s(tr[phx-click="select"][phx-value-cwe="CWE-707"]))
      |> render_click()

    assert_patched(lv, ~p"/common-weaknesses?cwe=CWE-707")
    assert html =~ "CVEs for"
    assert html =~ "CVE-2025-0001"
    assert html =~ "CVE-2025-0002"
  end

  test "a direct cwe URL shows the filtered list", %{conn: conn} do
    {:ok, _lv, html} = live(conn, ~p"/common-weaknesses?cwe=CWE-707")

    assert html =~ "CVEs for"
    assert html =~ "CVE-2025-0001"
  end

  test "clear removes the filtered list", %{conn: conn} do
    {:ok, lv, _html} = live(conn, ~p"/common-weaknesses?cwe=CWE-707")

    assert render(lv) =~ "CVEs for"

    html = lv |> element(~s(button[phx-click="clear"])) |> render_click()

    assert_patched(lv, ~p"/common-weaknesses")
    refute html =~ "CVEs for"
  end
end
