# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesControllerTest do
  use VarselWeb.ConnCase, async: false

  alias Varsel.CVE.CveRecord
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessRelationship

  # 1000 (Research Concepts, member) -> 707 (member) -> 74 -> 79.
  # Plus two isolated branches with no CVEs anywhere in them, for the
  # empty-state matrix: 400 (member, has child 401, zero CVEs) and 500
  # (leaf member, zero CVEs).
  defp seed_cwe_tree do
    Ash.Seed.seed!(View, %{
      view_id: 1000,
      name: "Research Concepts",
      type: :graph,
      status: :stable,
      objective: "Research Concepts objective"
    })

    for {id, name} <- [
          {707, "Improper Neutralization"},
          {74, "Injection"},
          {79, "Cross-site Scripting"},
          {400, "Resource Lifecycle"},
          {401, "Missing Release"},
          {500, "Nonexistent Class"}
        ] do
      Ash.create!(
        Weakness,
        %{
          cwe_id: id,
          name: name,
          abstraction: :class,
          status: :stable,
          description: "#{name} description"
        },
        action: :upsert,
        authorize?: false
      )
    end

    for cwe_id <- [707, 400, 500],
        do: Ash.Seed.seed!(ViewMembership, %{view_id: 1000, cwe_id: cwe_id})

    for {source, target} <- [{79, 74}, {74, 707}, {401, 400}] do
      Ash.Seed.seed!(WeaknessRelationship, %{
        source_cwe_id: source,
        target_cwe_id: target,
        nature: :child_of,
        view_id: 1000
      })
    end

    Varsel.Repo.query!("REFRESH MATERIALIZED VIEW cwe_weakness_closure")
  end

  defp publish_cve(cve_id, cwe_id), do: publish_cve_with_cwes(cve_id, [cwe_id])

  defp publish_cve_with_cwes(cve_id, cwe_ids) do
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
            %{
              "descriptions" =>
                Enum.map(cwe_ids, fn cwe_id ->
                  %{"cweId" => "CWE-#{cwe_id}", "lang" => "en", "type" => "CWE"}
                end)
            }
          ],
          "references" => []
        }
      }
    }

    Ash.create!(CveRecord, %{cve_json: cve_json}, action: :import, authorize?: false)
  end

  setup do
    seed_cwe_tree()
    publish_cve("CVE-2025-8001", 79)
    publish_cve("CVE-2025-8002", 74)
    :ok
  end

  test "GET /common-weaknesses redirects to the default view", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses")

    assert redirected_to(conn, 302) == ~p"/common-weaknesses/1000"
  end

  test "the legacy .html path still redirects", %{conn: conn} do
    conn = get(conn, "/common-weaknesses.html")

    assert redirected_to(conn, 301) == ~p"/common-weaknesses"
  end

  test "the view root's main header is the CMS page identity, not the view", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/1000")
    html = html_response(conn, 200)

    assert html =~ ~s(<h1 class="page-header-title text-2xl font-bold leading-tight">)
    assert html =~ "Common Weaknesses"
    # The view is named in the quiet view-note panel, not the h1.
    assert html =~ "Research Concepts"
  end

  test "the view root renders declared members with recursive counts and links", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/1000")
    html = html_response(conn, 200)

    assert html =~ "Improper Neutralization"
    # 707's subtree (707, 74, 79) reaches both published CVEs.
    assert html =~ ~s(href="/common-weaknesses/1000/707")
  end

  test "the legend renders as a genuine CSS-table formatting context, not foster-parented rows",
       %{
         conn: conn
       } do
    # 707's drill-down has exactly one child (74), carrying both published
    # CVEs (100%) — one predictable legend row to assert cell shape on.
    conn = get(conn, ~p"/common-weaknesses/1000/707")
    html = html_response(conn, 200)
    doc = LazyHTML.from_document(html)

    table = LazyHTML.query(doc, ".cwe-legend-table")
    assert Enum.count(table) == 1

    # The rows must be direct children of the table container — if the
    # browser had foster-parented a real <a> row out of a <table>/<tbody>,
    # a `>` child-combinator query from the container would find nothing.
    rows = LazyHTML.query(doc, ".cwe-legend-table > .cwe-legend-row")
    assert Enum.count(rows) == 1

    count_cells =
      LazyHTML.query(doc, ".cwe-legend-table > .cwe-legend-row > .cwe-legend-cell-count")

    pct_cells = LazyHTML.query(doc, ".cwe-legend-table > .cwe-legend-row > .cwe-legend-cell-pct")
    assert Enum.count(count_cells) == 1
    assert Enum.count(pct_cells) == 1

    # Count and percentage render as separate cells, not one combined string.
    assert LazyHTML.text(count_cells) =~ ~r/^\s*2\s*$/
    assert LazyHTML.text(pct_cells) =~ "100.0%"
  end

  test "the view root renders its own embedded CVE table when the view has published CVEs", %{
    conn: conn
  } do
    conn = get(conn, ~p"/common-weaknesses/1000")
    html = html_response(conn, 200)

    assert html =~ "Every CVE in this view"
    assert html =~ ~s(class="table table-zebra")
  end

  test "the view root has no embedded CVE table when the view has no published CVEs", %{
    conn: conn
  } do
    Ash.Seed.seed!(View, %{
      view_id: 2000,
      name: "Empty View",
      type: :graph,
      status: :stable,
      objective: "Empty view objective"
    })

    Ash.Seed.seed!(ViewMembership, %{view_id: 2000, cwe_id: 500})
    Varsel.Repo.query!("REFRESH MATERIALIZED VIEW cwe_weakness_closure")

    conn = get(conn, ~p"/common-weaknesses/2000")
    html = html_response(conn, 200)

    refute html =~ "Every CVE in this view"
    refute html =~ ~s(class="table table-zebra")
  end

  test "the drill-down renders direct children, their counts, and up-links", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/1000/707")
    html = html_response(conn, 200)

    assert html =~ "Injection"
    assert html =~ ~s(href="/common-weaknesses/1000/74")
    # Up-link back to the view root.
    assert html =~ ~s(href="/common-weaknesses/1000")
    assert html =~ "Research Concepts"
  end

  test "a leaf CWE's drill-down renders with no children and an up-link to its parent", %{
    conn: conn
  } do
    conn = get(conn, ~p"/common-weaknesses/1000/79")
    html = html_response(conn, 200)

    assert html =~ "Cross-site Scripting"
    assert html =~ ~s(href="/common-weaknesses/1000/74")
  end

  test "the view root panel links to the view's official page at MITRE", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/1000")
    html = html_response(conn, 200)

    assert html =~ ~s(href="https://cwe.mitre.org/data/definitions/1000.html")
    assert html =~ "MITRE"
  end

  test "the drill-down header links to the current weakness's official page at MITRE", %{
    conn: conn
  } do
    conn = get(conn, ~p"/common-weaknesses/1000/79")
    html = html_response(conn, 200)

    assert html =~ ~s(href="https://cwe.mitre.org/data/definitions/79.html")
    assert html =~ "MITRE"
  end

  describe "the view switcher" do
    test "lists a members-having view, omits one with no members, omits deprecated/obsolete", %{
      conn: conn
    } do
      # Has a member -> switchable.
      Ash.Seed.seed!(View, %{
        view_id: 699,
        name: "Software Development",
        type: :graph,
        status: :stable,
        objective: "Software Development objective"
      })

      Ash.Seed.seed!(ViewMembership, %{view_id: 699, cwe_id: 707})

      # No declared members -> not switchable, even though it's a real view.
      Ash.Seed.seed!(View, %{
        view_id: 1003,
        name: "Weaknesses for Simplified Mapping of Published Vulnerabilities",
        type: :graph,
        status: :stable,
        objective: "No members objective"
      })

      # Has a member but deprecated -> not switchable.
      Ash.Seed.seed!(View, %{
        view_id: 1100,
        name: "Retired View",
        type: :graph,
        status: :deprecated,
        objective: "Retired view objective"
      })

      Ash.Seed.seed!(ViewMembership, %{view_id: 1100, cwe_id: 707})

      # Has a member but obsolete -> not switchable.
      Ash.Seed.seed!(View, %{
        view_id: 1200,
        name: "Obsolete View",
        type: :graph,
        status: :obsolete,
        objective: "Obsolete view objective"
      })

      Ash.Seed.seed!(ViewMembership, %{view_id: 1200, cwe_id: 707})

      conn = get(conn, ~p"/common-weaknesses/1000")
      html = html_response(conn, 200)
      doc = LazyHTML.from_document(html)

      dropdown_text =
        doc |> LazyHTML.query(".dropdown-content.menu") |> LazyHTML.text()

      assert dropdown_text =~ "Software Development"
      refute dropdown_text =~ "Weaknesses for Simplified Mapping"
      refute dropdown_text =~ "Retired View"
      refute dropdown_text =~ "Obsolete View"
    end

    test "the current view is marked, not a link to itself", %{conn: conn} do
      conn = get(conn, ~p"/common-weaknesses/1000")
      html = html_response(conn, 200)
      doc = LazyHTML.from_document(html)

      current = LazyHTML.query(doc, ".dropdown-content.menu span.menu-active")
      assert LazyHTML.text(current) =~ "Research Concepts"

      current_links = LazyHTML.query(doc, ~s(a[href="/common-weaknesses/1000"].menu-active))
      assert Enum.empty?(current_links)
    end
  end

  test "the donut center shows the view's own recursive total, not the slice-sum", %{conn: conn} do
    # A CVE tagged with two member subtrees (707, 400) counts once in EACH
    # member's slice (slice-sum goes up by 2) but only once in the view's
    # distinct recursive total — the two numbers now provably diverge.
    publish_cve_with_cwes("CVE-2025-8003", [707, 400])

    conn = get(conn, ~p"/common-weaknesses/1000")
    html = html_response(conn, 200)
    doc = LazyHTML.from_document(html)

    # Slice-sum: 707's subtree now has 3 CVEs (8001, 8002, 8003), 400 has 1
    # (8003) => 4. Distinct view total: 3 CVEs overall (8001, 8002, 8003).
    center_text =
      doc
      |> LazyHTML.query(~s(svg.cwe-donut-svg text[font-weight="bold"]))
      |> LazyHTML.text()

    assert center_text =~ ~r/^\s*3\s*$/
    refute center_text =~ ~r/^\s*4\s*$/
  end

  describe "empty-state matrix (children x recursive CVE total)" do
    test "children > 0, cves > 0 -> donut + legend + table", %{conn: conn} do
      conn = get(conn, ~p"/common-weaknesses/1000/707")
      html = html_response(conn, 200)

      assert html =~ "cwe-chart-wrapper"
      assert html =~ "CVEs for Improper Neutralization"
    end

    test "children > 0, cves = 0 -> grey-ring donut + legend, no table", %{conn: conn} do
      conn = get(conn, ~p"/common-weaknesses/1000/400")
      html = html_response(conn, 200)

      assert html =~ "cwe-chart-wrapper"
      assert html =~ "cwe-donut-empty-ring"
      # The all-zero legend still links its (only) row through.
      assert html =~ "Missing Release"
      assert html =~ ~s(href="/common-weaknesses/1000/401")
      refute html =~ "CVEs for"
    end

    test "children = 0, cves > 0 -> table only, no donut/legend", %{conn: conn} do
      conn = get(conn, ~p"/common-weaknesses/1000/79")
      html = html_response(conn, 200)

      refute html =~ "cwe-chart-wrapper"
      assert html =~ "CVEs for Cross-site Scripting"
    end

    test "children = 0, cves = 0 -> no donut, no table, a quiet empty-state note", %{conn: conn} do
      conn = get(conn, ~p"/common-weaknesses/1000/500")
      html = html_response(conn, 200)

      refute html =~ "cwe-chart-wrapper"
      refute html =~ "CVEs for"
      assert html =~ "No published CVEs reference this weakness."
    end
  end

  test "an unknown view_id 404s", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/9999")

    assert html_response(conn, 404)
  end

  test "a non-numeric view_id 404s", %{conn: conn} do
    conn = get(conn, "/common-weaknesses/abc")

    assert html_response(conn, 404)
  end

  test "a non-numeric cwe_id 404s", %{conn: conn} do
    conn = get(conn, "/common-weaknesses/1000/abc")

    assert html_response(conn, 404)
  end

  test "an unknown cwe_id 404s", %{conn: conn} do
    conn = get(conn, ~p"/common-weaknesses/1000/424242")

    assert html_response(conn, 404)
  end

  test "a weakness that exists but is outside this view 404s", %{conn: conn} do
    Ash.create!(
      Weakness,
      %{
        cwe_id: 999,
        name: "Outside",
        abstraction: :class,
        status: :stable,
        description: "Outside"
      },
      action: :upsert,
      authorize?: false
    )

    conn = get(conn, ~p"/common-weaknesses/1000/999")

    assert html_response(conn, 404)
  end
end
