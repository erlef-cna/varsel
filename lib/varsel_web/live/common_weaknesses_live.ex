# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesLive do
  @moduledoc """
  Interactive CWE distribution donut.

  State lives entirely in the URL so any view is linkable:

    * `?focus=CWE-NNN` — drill-down root (which node's children the donut shows)
    * `?cwe=CWE-NNN` — the selected weakness whose CVEs are listed inline below

  Clicking a slice drills down (if the node has children) or selects it;
  clicking a legend row selects the node to show its filtered CVE list.
  """
  use VarselWeb, :live_view

  import VarselWeb.ChartComponents, only: [cwe_donut: 1, cwe_legend: 1]
  import VarselWeb.CveView, only: [package_ref: 1]

  alias Varsel.CVE
  alias VarselWeb.Charts

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    page = Varsel.Content.get_page!("common-weaknesses")
    {:ok, assign(socket, page: page, page_title: page.title)}
  end

  @impl Phoenix.LiveView
  def handle_params(params, _uri, socket) do
    focus = normalize_cwe(params["focus"])
    selected = normalize_cwe(params["cwe"])

    dist = focus |> Charts.cwe_distribution() |> Charts.donut_geometry()

    selected_entry = Enum.find(dist.entries, &(&1.id == selected))

    breadcrumb_links =
      Enum.map(dist.breadcrumb, fn crumb ->
        %{name: crumb.name, focus: crumb.id, to: chart_path(crumb.id, nil)}
      end)

    {:noreply,
     assign(socket,
       focus: focus,
       selected: selected,
       dist: dist,
       breadcrumb_links: breadcrumb_links,
       selected_entry: selected_entry,
       selected_cves: load_cves(selected_entry)
     )}
  end

  # A slice: drill down when it has children, otherwise select it for the list.
  @impl Phoenix.LiveView
  def handle_event("slice", %{"cwe" => cwe, "drill" => "true"}, socket) do
    {:noreply, push_patch(socket, to: chart_path(cwe, nil))}
  end

  def handle_event("slice", %{"cwe" => cwe}, socket) do
    {:noreply, push_patch(socket, to: chart_path(socket.assigns.focus, cwe))}
  end

  # A legend row: select the node to filter the CVE list.
  def handle_event("select", %{"cwe" => cwe}, socket) do
    {:noreply, push_patch(socket, to: chart_path(socket.assigns.focus, cwe))}
  end

  def handle_event("up", _params, socket) do
    parent =
      case socket.assigns.dist.breadcrumb do
        [] -> nil
        crumb -> crumb |> Enum.drop(-1) |> List.last() |> then(&(&1 && &1.id))
      end

    {:noreply, push_patch(socket, to: chart_path(parent, nil))}
  end

  def handle_event("clear", _params, socket) do
    {:noreply, push_patch(socket, to: chart_path(socket.assigns.focus, nil))}
  end

  defp chart_path(focus, cwe) do
    query =
      Enum.reject([focus: focus, cwe: cwe], fn {_k, v} -> is_nil(v) end)

    case query do
      [] -> ~p"/common-weaknesses"
      q -> ~p"/common-weaknesses?#{q}"
    end
  end

  defp load_cves(nil), do: []

  defp load_cves(%{cve_ids: cve_ids}) do
    [load: [:cve_id, :title, :date_published, :purls], actor: nil]
    |> CVE.list_published_cve_records!()
    |> Enum.filter(&(&1.cve_id in cve_ids))
  end

  defp normalize_cwe(nil), do: nil
  defp normalize_cwe(""), do: nil
  defp normalize_cwe("CWE-" <> _ = cwe), do: cwe
  defp normalize_cwe(n), do: "CWE-#{n}"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-5xl py-10">
      <header class="mb-8 pb-6 border-b border-base-300">
        <p class="eef-eyebrow mb-2">Analysis</p>
        <h1 class="text-3xl sm:text-4xl font-bold">{@page.title}</h1>
      </header>

      <div class="prose prose-base max-w-none mb-6">{raw(@page.body)}</div>

      <%!-- Breadcrumb / drill-down controls --%>
      <nav :if={@breadcrumb_links != []} class="flex items-center flex-wrap gap-1 text-sm mb-4">
        <.link patch={chart_path(nil, nil)} class="link link-primary">All classes</.link>
        <span :for={crumb <- @breadcrumb_links} class="flex items-center gap-1">
          <.icon name="hero-chevron-right-micro" class="size-3.5 text-base-content/40" />
          <.link :if={crumb.focus != @focus} patch={crumb.to} class="link link-hover">{crumb.name}</.link>
          <span :if={crumb.focus == @focus} class="text-base-content/70">{crumb.name}</span>
        </span>
      </nav>

      <div class="cwe-chart-wrapper">
        <div class="cwe-donut"><.cwe_donut data={@dist} /></div>
        <div class="cwe-legend">
          <p class="text-xs text-base-content/50 mb-2">
            Click a slice to drill down · click a row to list its CVEs
          </p>
          <.cwe_legend data={@dist} />
        </div>
      </div>

      <%!-- Inline filtered CVE list --%>
      <section :if={@selected_entry} class="mt-8 pt-6 border-t border-base-300">
        <div class="flex items-center justify-between mb-4">
          <div>
            <p class="eef-eyebrow mb-1">Filtered</p>
            <h2 class="text-xl font-bold">
              CVEs for {@selected_entry.name}
              <span class="text-base-content/50 font-normal text-base">{@selected_entry.id}</span>
            </h2>
          </div>
          <button type="button" phx-click="clear" class="btn btn-ghost btn-sm">
            <.icon name="hero-x-mark-micro" class="size-4" /> Clear
          </button>
        </div>

        <div class="overflow-x-auto">
          <table class="table table-zebra">
            <thead>
              <tr>
                <th>Summary</th>
                <th>Publication</th>
                <th>CVE ID</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={record <- @selected_cves}>
                <td>
                  <.link navigate={~p"/cves/#{record.cve_id}"} class="link link-primary font-medium">
                    {record.title || record.cve_id}
                  </.link>
                </td>
                <td>
                  <div :for={purl <- record.purls || []} class="text-sm">
                    <.package_ref entry={%{"packageURL" => purl}} link={true} />
                  </div>
                </td>
                <td class="whitespace-nowrap">{record.cve_id}</td>
                <td class="whitespace-nowrap">{format_date(record.date_published)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
    """
  end

  defp format_date(nil), do: "—"
  defp format_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
end
