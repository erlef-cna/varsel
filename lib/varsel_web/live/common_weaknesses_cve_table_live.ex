# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CommonWeaknessesCveTableLive do
  @moduledoc """
  The paged CVE table on the common-weaknesses view root and drill-down
  pages — a small LiveView `live_render/3`-embedded into the dead
  controller-rendered page (`common_weaknesses_html/{view,show}.html.heex`),
  the same pattern `VarselWeb.AffectedCheckerLive` uses on the CVE detail
  page, since the page itself needs no other interactivity.

  Static public data: loads once on mount plus re-reads on page change, no
  PubSub/`keep_live` — nothing here needs to react to a write happening
  elsewhere while the page sits open. Offset pagination is driven by
  `Ash.page!/2` directly rather than `VarselWeb.LivePagination`: that helper
  (like the `keep_live` machinery it wraps) reads and writes
  `socket.assigns.ash_live_config`, which only exists for a `keep_live`-kept
  assign — this page is a plain one-shot read, so there is no such config to
  update.

  Pagination lives on `:list_published` itself, `required?: false` — a call
  with no `page:` opt still gets a bare list back; this table is the one
  caller that passes one.

  Selects no base attributes — crucially not `cve_json`, the one large
  column on the table — and strict-loads only the four calculations the
  rendered row actually reads. `:list_published`'s own `prepare` also always
  loads `:date_updated` (shared by every other caller of the action); that
  one small SQL-fragment calc rides along unused here rather than forking
  the action just to drop it.
  """
  use VarselWeb, :live_view

  import VarselWeb.CveView, only: [package_display_name: 1]

  alias AshPhoenix.LiveView, as: AshLiveView
  alias Varsel.CVE
  alias Varsel.CVE.CveRecord

  @impl Phoenix.LiveView
  def mount(_params, %{"view_id" => view_id, "cwe_id" => cwe_id}, socket) do
    socket = assign(socket, view_id: view_id, cwe_id: cwe_id)
    {:ok, assign(socket, :page, fetch_page(socket, page: [limit: 25, offset: 0, count: true]))}
  end

  @impl Phoenix.LiveView
  def handle_event("paginate", %{"page" => target}, socket) when target in ["prev", "next", "first", "last"] do
    page = Ash.page!(socket.assigns.page, String.to_existing_atom(target))
    {:noreply, assign(socket, :page, page)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    page = socket.assigns.page

    socket =
      with {number, ""} <- Integer.parse(target),
           true <- number >= 1,
           last_page when is_integer(last_page) <- AshLiveView.last_page(page),
           true <- number <= last_page do
        assign(socket, :page, Ash.page!(page, number))
      else
        _ -> socket
      end

    {:noreply, socket}
  end

  defp fetch_page(socket, opts) do
    CVE.list_published_cve_records!(
      %{view_id: socket.assigns.view_id, cwe_id: socket.assigns.cwe_id},
      opts
      |> Keyword.put(:actor, nil)
      |> Keyword.put(:query, Ash.Query.select(CveRecord, []))
      |> Keyword.put(:load, [:cve_id, :title, :date_published, :purls])
      |> Keyword.put(:strict?, true)
    )
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <.list_card>
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
            <tr
              :for={record <- @page.results}
              class="cursor-pointer hover:bg-base-300/40"
              phx-click={JS.navigate(~p"/cves/#{record.cve_id <> ".html"}")}
            >
              <td>
                <span class="link link-primary font-medium">{record.title || record.cve_id}</span>
              </td>
              <td phx-click={%JS{}}>
                <div :for={purl <- record.purls || []} class="text-sm">
                  <.package_display_name purl={purl} link={true} />
                </div>
              </td>
              <td class="whitespace-nowrap font-mono text-xs">{record.cve_id}</td>
              <td class="whitespace-nowrap">{format_date(record.date_published)}</td>
            </tr>
          </tbody>
        </table>

        <.empty_state :if={@page.results == []}>No CVEs match this weakness.</.empty_state>
      </div>

      <:footer :if={paged?(@page)}>
        <.pagination page={@page} noun="CVE" />
      </:footer>
    </.list_card>
    """
  end
end
