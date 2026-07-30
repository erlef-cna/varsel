# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesCveTableLiveTest do
  use VarselWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias Varsel.CVE.CveRecord
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessRelationship
  alias VarselWeb.CommonWeaknessesCveTableLive

  defp seed_cwe_tree do
    Ash.Seed.seed!(View, %{
      view_id: 1000,
      name: "Research Concepts",
      type: :graph,
      status: :stable,
      objective: "objective"
    })

    for {id, name} <- [{707, "Improper Neutralization"}, {74, "Injection"}, {79, "XSS"}] do
      Ash.create!(
        Weakness,
        %{cwe_id: id, name: name, abstraction: :class, status: :stable, description: name},
        action: :upsert,
        authorize?: false
      )
    end

    Ash.Seed.seed!(ViewMembership, %{view_id: 1000, cwe_id: 707})

    for {source, target} <- [{79, 74}, {74, 707}] do
      Ash.Seed.seed!(WeaknessRelationship, %{
        source_cwe_id: source,
        target_cwe_id: target,
        nature: :child_of,
        view_id: 1000
      })
    end

    Varsel.Repo.query!("REFRESH MATERIALIZED VIEW cwe_weakness_closure")
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

  defp mount(conn, view_id, cwe_id) do
    live_isolated(conn, CommonWeaknessesCveTableLive, session: %{"view_id" => view_id, "cwe_id" => cwe_id})
  end

  setup do
    seed_cwe_tree()
    :ok
  end

  test "a nil cwe_id (whole-view) session lists every CVE in the view", %{conn: conn} do
    publish_cve("CVE-2025-9001", 79)
    publish_cve("CVE-2025-9002", 707)

    {:ok, _lv, html} = mount(conn, 1000, nil)

    assert html =~ "CVE-2025-9001"
    assert html =~ "CVE-2025-9002"
  end

  test "a drill-down session (cwe_id set) lists only that subtree", %{conn: conn} do
    publish_cve("CVE-2025-9003", 79)
    publish_cve("CVE-2025-9004", 707)

    {:ok, _lv, html} = mount(conn, 1000, 74)

    assert html =~ "CVE-2025-9003"
    refute html =~ "CVE-2025-9004"
  end

  test "no results renders the empty state", %{conn: conn} do
    {:ok, _lv, html} = mount(conn, 1000, 79)

    assert html =~ "No CVEs match this weakness."
  end

  test "pagination controls appear only when results exceed one page, and page 2 shows the rest",
       %{conn: conn} do
    for n <- 1..30 do
      publish_cve("CVE-2025-#{9100 + n}", 79)
    end

    {:ok, lv, html} = mount(conn, 1000, 79)

    assert html =~ "25 per page"
    assert page_input_value(html) == "1"

    html = lv |> element(~s(button[phx-value-page="next"])) |> render_click()

    assert page_input_value(html) == "2"
  end

  defp page_input_value(html) do
    [_full, value] = Regex.run(~r/name="page" value="(\d+)"/, html)
    value
  end
end
