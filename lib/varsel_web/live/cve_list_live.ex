# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveListLive do
  @moduledoc """
  Public list of published CVE records — the Phoenix port of the Jekyll site's
  `cves/index.md` table, enhanced with live full-text search (the `:search`
  read action) and sortable publication/update dates.
  """
  use VarselWeb, :live_view

  import VarselWeb.CveView, only: [package_ref: 1]

  alias Varsel.CVE

  @load [:cve_id, :title, :date_published, :date_updated, :purls]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(page_title: "Issued CVEs", query: "", sort: :date_published)
      |> load_records()

    {:ok, socket}
  end

  @impl Phoenix.LiveView
  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, socket |> assign(query: query) |> load_records()}
  end

  def handle_event("sort", %{"by" => by}, socket) do
    {:noreply, socket |> assign(sort: String.to_existing_atom(by)) |> load_records()}
  end

  defp load_records(socket) do
    query = socket.assigns.query

    records =
      if String.trim(query) == "" do
        CVE.list_published_cve_records!(load: @load, actor: nil)
      else
        CVE.search_cve_records!(query, load: @load, actor: nil)
      end

    assign(socket, records: sort_records(records, socket.assigns.sort))
  end

  defp sort_records(records, sort) when sort in [:date_published, :date_updated] do
    Enum.sort_by(records, &Map.get(&1, sort), {:desc, DateTime})
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-8">
      <.header>
        Issued CVEs
        <:subtitle>Vulnerabilities assigned and published by the EEF CNA.</:subtitle>
      </.header>

      <form id="cve-search" phx-change="search" phx-submit="search" class="my-6">
        <input
          type="search"
          name="query"
          value={@query}
          placeholder="Search by ID, title, package, description…"
          autocomplete="off"
          phx-debounce="200"
          class="input input-bordered w-full max-w-lg"
        />
      </form>

      <div class="overflow-x-auto">
        <table class="table table-zebra">
          <thead>
            <tr>
              <th>Summary</th>
              <th>Publication</th>
              <th>CVE ID</th>
              <th>
                <button
                  type="button"
                  phx-click="sort"
                  phx-value-by="date_published"
                  class="link link-hover"
                >
                  Published
                </button>
              </th>
              <th>
                <button
                  type="button"
                  phx-click="sort"
                  phx-value-by="date_updated"
                  class="link link-hover"
                >
                  Last Updated
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr :for={record <- @records}>
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
              <td class="whitespace-nowrap">{format_date(record.date_updated)}</td>
            </tr>
            <tr :if={@records == []}>
              <td colspan="5" class="text-center text-base-content/60 py-8">
                No CVEs match your search.
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="mt-6 text-sm text-base-content/60">
        Machine-readable: <a href={~p"/cves/index.json"} class="link">CVE index (JSON)</a>
        · <a href={~p"/osv/all.json"} class="link">OSV feed (JSON)</a>
        · <a href={~p"/feed.atom"} class="link">Atom</a>
        · <a href={~p"/feed.rss"} class="link">RSS</a>
      </p>
    </div>
    """
  end

  defp format_date(nil), do: "—"
  defp format_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
end
