# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesController do
  @moduledoc """
  Public CWE distribution browser: a view root (donut of its declared
  members) and a per-CWE drill-down (donut of that CWE's direct children),
  both scoped to one CWE view and both backed by the recursive
  `cwe_weakness_closure` materialized view for slice counts — never a
  load-everything scan of published CVEs.
  """
  use VarselWeb, :controller

  alias Ash.Error.Invalid
  alias Varsel.CVE
  alias Varsel.CWE
  alias Varsel.CWE.View
  alias Varsel.CWE.ViewMembership
  alias Varsel.CWE.Weakness
  alias Varsel.CWE.WeaknessRelationship
  alias VarselWeb.Charts

  @default_view_id 1000

  def index(conn, _params) do
    redirect(conn, to: ~p"/common-weaknesses/#{@default_view_id}")
  end

  def view(conn, %{"view_id" => view_id}) do
    view =
      CWE.get_view!(view_id,
        query: Ash.Query.select(View, [:view_id, :name]),
        strict?: true,
        actor: nil
      )

    page = Varsel.Content.get_page!("common-weaknesses")

    members =
      CWE.list_view_memberships_by_view!(%{view_id: view.view_id},
        query: Ash.Query.select(ViewMembership, [:cwe_id]),
        load: [weakness: Ash.Query.select(Weakness, [:name])],
        strict?: true,
        actor: nil
      )

    counts = counts_by_cwe_id(view.view_id, Enum.map(members, & &1.cwe_id))

    entries =
      members
      |> Enum.map(fn membership ->
        %{
          id: "CWE-#{membership.cwe_id}",
          name: membership.weakness.name,
          count: Map.get(counts, membership.cwe_id, 0),
          href: ~p"/common-weaknesses/#{view.view_id}/#{membership.cwe_id}"
        }
      end)
      |> Enum.sort_by(& &1.count, :desc)

    # The view's own recursive total (NULL-parent closure) — NOT the sum of
    # member slice counts, which double-counts CVEs reachable through more
    # than one member's overlapping subtree.
    cve_total = view_total(view.view_id)

    conn
    |> assign(:page_title, page.title)
    |> render(:view,
      view: view,
      page: page,
      dist: donut_data(entries, cve_total),
      cve_total: cve_total,
      mitre_url: mitre_url(view.view_id),
      switchable_views:
        CWE.list_switchable_views!(
          query: Ash.Query.select(View, [:view_id, :name]),
          strict?: true,
          actor: nil
        )
    )
  rescue
    Invalid -> render_404(conn)
  end

  def show(conn, %{"view_id" => view_id, "cwe_id" => cwe_id}) do
    view =
      CWE.get_view!(view_id,
        query: Ash.Query.select(View, [:view_id, :name]),
        strict?: true,
        actor: nil
      )

    weakness =
      CWE.get_weakness!(cwe_id,
        query: Ash.Query.select(Weakness, [:cwe_id, :name, :description]),
        strict?: true,
        actor: nil
      )

    if !in_view?(view.view_id, weakness.cwe_id), do: raise(Invalid, errors: [])

    page = Varsel.Content.get_page!("common-weaknesses")

    children =
      CWE.list_weakness_children!(%{view_id: view.view_id, cwe_id: weakness.cwe_id},
        query: Ash.Query.select(WeaknessRelationship, [:source_cwe_id]),
        load: [source: Ash.Query.select(Weakness, [:name])],
        strict?: true,
        actor: nil
      )

    parents =
      %{view_id: view.view_id, cwe_id: weakness.cwe_id}
      |> CWE.list_weakness_parents!(
        query: Ash.Query.select(WeaknessRelationship, [:target_cwe_id]),
        load: [target: Ash.Query.select(Weakness, [:cwe_id, :name])],
        strict?: true,
        actor: nil
      )
      |> Enum.map(& &1.target)

    counts = counts_by_cwe_id(view.view_id, Enum.map(children, & &1.source_cwe_id))

    entries =
      children
      |> Enum.map(fn rel ->
        %{
          id: "CWE-#{rel.source_cwe_id}",
          name: rel.source.name,
          count: Map.get(counts, rel.source_cwe_id, 0),
          href: ~p"/common-weaknesses/#{view.view_id}/#{rel.source_cwe_id}"
        }
      end)
      |> Enum.sort_by(& &1.count, :desc)

    # This node's own recursive total (its subtree) — NOT the sum of child
    # slice counts, which double-counts through overlapping sibling subtrees
    # and misses CVEs attached to the node itself or between it and its
    # children.
    cve_total = weakness_total(view.view_id, weakness.cwe_id)

    conn
    |> assign(:page_title, "#{weakness.name} · #{page.title}")
    |> render(:show,
      view: view,
      weakness: weakness,
      parents: parents,
      page: page,
      dist: donut_data(entries, cve_total),
      has_children?: children != [],
      cve_total: cve_total,
      mitre_url: mitre_url(weakness.cwe_id)
    )
  rescue
    Invalid -> render_404(conn)
  end

  defp in_view?(view_id, cwe_id) do
    CWE.cwe_in_view?(%{view_id: view_id, cwe_id: cwe_id}, actor: nil)
  end

  defp counts_by_cwe_id(_view_id, []), do: %{}

  defp counts_by_cwe_id(view_id, cwe_ids) do
    %{view_id: view_id, cwe_ids: cwe_ids}
    |> CVE.count_published_cve_records_by_cwe_subtree!(actor: nil)
    |> Map.new()
  end

  defp view_total(view_id) do
    CVE.count_published_cve_records_in_cwe_view!(%{view_id: view_id, cwe_id: nil}, actor: nil)
  end

  defp weakness_total(view_id, cwe_id) do
    CVE.count_published_cve_records_in_cwe_view!(%{view_id: view_id, cwe_id: cwe_id}, actor: nil)
  end

  # donut_geometry/1 gives a zero-count entry a degenerate (invisible) arc
  # rather than dropping it — it still shows in the legend at 0%, still
  # links to its drill-down page. center_total is the page's own recursive
  # total, not the slice-sum: it's what the donut's center number displays.
  defp donut_data(entries, center_total), do: Charts.donut_geometry(%{entries: entries, center_total: center_total})

  defp mitre_url(cwe_id), do: "https://cwe.mitre.org/data/definitions/#{cwe_id}.html"

  defp render_404(conn) do
    conn
    |> put_status(:not_found)
    |> put_view(html: VarselWeb.ErrorHTML)
    |> render("404.html")
  end
end
