# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveListLive do
  @moduledoc """
  The CVE list — one page for two audiences.

  Visitors (and non-POC users) get the public list of published CVEs with
  full-text search, paginated; the `:list_all` read policy scopes them to
  published records. POCs get the management console on top: the header band
  with MITRE sync and pool actions, one stat tile per lifecycle state (the
  overview and the filter are the same control), and per-row edit/reject.
  Editing a record's JSON lives on `VarselWeb.VarselEditLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CveView, only: [package_ref: 1]
  import VarselWeb.LivePagination, only: [change_page: 3]

  alias Varsel.CVE
  alias Varsel.CVE.CveRecord

  require Ash.Query

  # States a record may be rejected from (the :reject state-machine `from` set).
  @rejectable [:reserved, :draft, :published]
  # States whose cve_json can be edited (:request_publish / :update `from` sets).
  @editable [:draft, :published, :pending_update]

  @states [:reserved, :draft, :publishing, :published, :pending_update, :rejected]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    poc? = poc?(socket.assigns.current_user)

    socket =
      socket
      |> assign(
        page_title: if(poc?, do: "CVE Management", else: "Issued CVEs"),
        poc?: poc?,
        mitre_syncing?: false,
        filter: "all",
        query: "",
        state_counts: %{},
        reject_record: nil
      )
      |> keep_records_live()

    {:ok, socket}
  end

  # (Re)binds the paginated record page to the current filter/search. On a
  # narrowing change the subscription is torn down first so keep_live can
  # re-subscribe without stacking duplicate PubSub deliveries.
  defp keep_records_live(socket) do
    socket.endpoint.unsubscribe("cve_record:all")

    opts = [subscribe: "cve_record:all", results: :lose]

    opts =
      if socket.assigns.poc?,
        do: Keyword.put(opts, :after_fetch, &assign_state_counts/2),
        else: opts

    keep_live(socket, :cve_records, &list_cve_records/2, opts)
  end

  @impl Phoenix.LiveView
  def handle_event("sync_with_mitre", _params, socket) do
    actor = socket.assigns.current_user

    socket =
      socket
      |> assign(mitre_syncing?: true)
      |> start_async(:mitre_sync, fn ->
        CVE.import_cves_from_mitre!(%{}, actor: actor)
        CVE.sync_reserved_cves_from_mitre!(%{}, actor: actor)

        CveRecord
        |> Ash.Query.filter(state == :published)
        |> Ash.bulk_update!(:sync_from_mitre, %{},
          actor: actor,
          notify?: true,
          return_errors?: true,
          strategy: :stream,
          allow_stream_with: :full_read
        )

        :ok
      end)

    {:noreply, socket}
  end

  def handle_event("reserve", _params, socket) do
    actor = socket.assigns.current_user

    pool_head =
      CVE.list_all_cve_records!(
        actor: actor,
        query: CveRecord |> Ash.Query.filter(state == :reserved) |> Ash.Query.limit(1)
      )

    socket =
      case pool_head do
        [] ->
          put_flash(socket, :error, "No reserved IDs in the pool.")

        [record] ->
          case CVE.assign_cve_record(record, %{}, actor: actor) do
            {:ok, drafted} ->
              # The list refreshes via the pub_sub notification handled above.
              put_flash(socket, :info, "Reserved #{drafted.cve_id} — now a draft.")

            {:error, error} ->
              put_flash(socket, :error, "Could not reserve: #{errors_to_string(error)}")
          end
      end

    {:noreply, socket}
  end

  def handle_event("reject_prompt", %{"id" => record_id}, socket) do
    record = Enum.find(socket.assigns.cve_records.results, &(&1.id == record_id))
    {:noreply, assign(socket, :reject_record, record)}
  end

  def handle_event("reject_cancel", _params, socket) do
    {:noreply, assign(socket, :reject_record, nil)}
  end

  def handle_event("reject", %{"record_id" => record_id, "rejection_reason" => reason}, socket) do
    actor = socket.assigns.current_user
    record = Enum.find(socket.assigns.cve_records.results, &(&1.id == record_id))

    socket =
      case CVE.reject_cve_record(record, %{rejection_reason: reason}, actor: actor) do
        {:ok, rejected} ->
          socket
          |> assign(:reject_record, nil)
          |> put_flash(:info, "Rejected #{rejected.cve_id}.")

        {:error, error} ->
          put_flash(socket, :error, "Could not reject: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  def handle_event("filter", %{"filter" => filter}, socket) do
    {:noreply, socket |> assign(filter: filter) |> keep_records_live()}
  end

  def handle_event("search", %{"query" => query}, socket) do
    {:noreply, socket |> assign(query: query) |> keep_records_live()}
  end

  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :cve_records, target)}
  end

  @impl Phoenix.LiveView
  def handle_async(:mitre_sync, {:ok, :ok}, socket) do
    {:noreply,
     socket
     |> assign(mitre_syncing?: false)
     |> put_flash(:info, "MITRE import and sync finished.")}
  end

  def handle_async(:mitre_sync, {:exit, reason}, socket) do
    {:noreply,
     socket
     |> assign(mitre_syncing?: false)
     |> put_flash(:error, "MITRE sync failed: #{Exception.format_exit(reason)}")}
  end

  # The keep_live callback: page_opts is nil on the first run and the stored
  # page (with the stability filter) on refetches/page changes.
  defp list_cve_records(socket, page_opts) do
    CVE.list_all_cve_records!(
      actor: socket.assigns.current_user,
      query: records_query(socket.assigns.filter, socket.assigns.query),
      page: page_opts || [count: true, offset: 0]
    )
  end

  # The tiles always show the whole pool, independent of the current
  # filter/search.
  defp assign_state_counts(_page, socket) do
    counts =
      [actor: socket.assigns.current_user, query: Ash.Query.select(CveRecord, [:state])]
      |> CVE.list_all_cve_records!()
      |> Enum.frequencies_by(& &1.state)

    assign(socket, :state_counts, counts)
  end

  defp records_query(filter, query) do
    CveRecord
    |> Ash.Query.load([:purls])
    |> filter_state(filter)
    |> filter_search(query)
  end

  defp filter_state(base, "all"), do: base

  defp filter_state(base, filter) do
    state = Enum.find(@states, &(to_string(&1) == filter)) || :none
    Ash.Query.filter(base, state == ^state)
  end

  # ID/title substring match plus the full-text search over the published
  # record bodies (reserved rows have no search vector and simply never
  # full-text-match).
  defp filter_search(base, query) do
    case query |> String.trim() |> String.downcase() do
      "" ->
        base

      term ->
        Ash.Query.filter(
          base,
          contains(string_downcase(cve_id), ^term) or
            contains(string_downcase(title), ^term) or
            matches_query(query: ^term)
        )
    end
  end

  defp tile_options(counts) do
    all = %{value: "all", label: "All records", count: counts |> Map.values() |> Enum.sum()}

    state_tiles =
      for state <- @states do
        %{
          value: to_string(state),
          label: Phoenix.Naming.humanize(state),
          count: Map.get(counts, state, 0),
          dot: state_dot(state)
        }
      end

    [all | state_tiles]
  end

  defp state_dot(:draft), do: "bg-warning"
  defp state_dot(:publishing), do: "bg-info"
  defp state_dot(:published), do: "bg-success"
  defp state_dot(:pending_update), do: "bg-info"
  defp state_dot(:rejected), do: "bg-error"
  defp state_dot(_reserved), do: "bg-base-content/30"

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  defp editable?(state), do: state in @editable
  defp rejectable?(state), do: state in @rejectable

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")

  defp count_label(count, singular) when is_integer(count) do
    if count == 1, do: "1 #{singular}", else: "#{count} #{singular}s"
  end

  defp count_label(_count, singular), do: "#{singular}s"

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.console_header
      eyebrow={if @poc?, do: "CNA Console", else: "EEF CNA"}
      title={if @poc?, do: "CVE records", else: "Issued CVEs"}
      subtitle={
        if @poc?,
          do: "Reserve, draft, publish, and reject CVE records.",
          else: "Vulnerabilities assigned and published by the EEF CNA."
      }
    >
      <:actions :if={@poc?}>
        <button
          class="btn btn-sm btn-eef-quiet"
          phx-click="sync_with_mitre"
          disabled={@mitre_syncing?}
        >
          {if @mitre_syncing?, do: "Syncing…", else: "Sync with MITRE"}
        </button>
        <button class="btn btn-sm btn-eef" phx-click="reserve">
          Reserve a new one
        </button>
      </:actions>
    </.console_header>

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6">
      <.stat_tiles :if={@poc?} active={@filter} options={tile_options(@state_counts)} />

      <div class={["rounded-box border border-base-300 bg-base-200 overflow-hidden", @poc? && "mt-4"]}>
        <div class="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-base-300">
          <span class="text-sm text-base-content/70 tabular-nums">
            {count_label(@cve_records.count, if(@poc?, do: "record", else: "CVE"))}
          </span>
          <form id="cve-record-search" phx-change="search" phx-submit="search">
            <.console_search
              value={@query}
              placeholder={
                if @poc?,
                  do: "Search CVE ID or title…",
                  else: "Search by ID, title, package, description…"
              }
            />
          </form>
        </div>

        <div class="overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>Summary</th>
                <th>Packages</th>
                <th>CVE ID</th>
                <th :if={@poc?}>State</th>
                <th>Published</th>
                <th>Updated</th>
                <th :if={@poc?}></th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={record <- @cve_records.results}
                class={["hover:bg-base-300/40", record.state == :reserved && "text-base-content/50"]}
              >
                <td class="max-w-md">
                  <.link
                    :if={record.state == :published}
                    navigate={~p"/cves/#{record.cve_id}"}
                    class="link link-hover font-semibold"
                  >
                    {record.title || record.cve_id}
                  </.link>
                  <span :if={record.state != :published}>{record.title || "—"}</span>
                </td>
                <td>
                  <div :for={purl <- record.purls || []} class="text-sm">
                    <.package_ref entry={%{"packageURL" => purl}} link={true} />
                  </div>
                </td>
                <td class="font-mono text-xs whitespace-nowrap">{record.cve_id || "—"}</td>
                <td :if={@poc?}>
                  <.state dot={state_dot(record.state)}>
                    {Phoenix.Naming.humanize(record.state)}
                  </.state>
                </td>
                <td class="whitespace-nowrap tabular-nums">{format_dt(record.date_published)}</td>
                <td class="whitespace-nowrap tabular-nums">{format_dt(record.date_updated)}</td>
                <td :if={@poc?}>
                  <div class="flex items-center gap-4 justify-end whitespace-nowrap">
                    <.link
                      :if={editable?(record.state)}
                      navigate={~p"/cves/manage/#{record.id}"}
                      class="link link-hover text-primary text-sm font-medium"
                    >
                      Edit
                    </.link>
                    <button
                      :if={rejectable?(record.state)}
                      type="button"
                      class="link link-hover text-error/80 text-sm"
                      phx-click="reject_prompt"
                      phx-value-id={record.id}
                    >
                      Reject…
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>

          <p :if={@cve_records.results == []} class="text-center text-base-content/60 py-8">
            No CVEs match your search.
          </p>
        </div>

        <div
          :if={is_integer(@cve_records.count) and @cve_records.count > @cve_records.limit}
          class="flex flex-wrap items-center justify-between gap-3 px-4 py-2 border-t border-base-300"
        >
          <span class="text-xs text-base-content/60">{@cve_records.limit} per page</span>
          <.pagination page={@cve_records} />
        </div>
      </div>

      <p class="mt-6 text-sm text-base-content/60">
        Machine-readable: <a href={~p"/cves/index.json"} class="link">CVE index (JSON)</a>
        · <a href={~p"/osv/all.json"} class="link">OSV feed (JSON)</a>
        · <a href={~p"/feed.atom"} class="link">Atom</a>
        · <a href={~p"/feed.rss"} class="link">RSS</a>
      </p>
    </div>

    <div :if={@reject_record} class="modal modal-open" id="reject-modal">
      <div class="modal-box max-w-sm">
        <h3 class="font-semibold text-lg mb-1">Reject {@reject_record.cve_id}</h3>
        <p class="text-sm text-base-content/60 mb-3">
          The rejection reason becomes part of the public record at MITRE.
        </p>
        <form phx-submit="reject">
          <input type="hidden" name="record_id" value={@reject_record.id} />
          <input
            type="text"
            name="rejection_reason"
            placeholder="Why is this record rejected?"
            required
            autofocus
            class="input input-bordered w-full"
          />
          <div class="modal-action">
            <button type="button" class="btn btn-ghost btn-sm" phx-click="reject_cancel">
              Cancel
            </button>
            <button type="submit" class="btn btn-error btn-sm">Reject record</button>
          </div>
        </form>
      </div>
      <div class="modal-backdrop" phx-click="reject_cancel"></div>
    </div>
    """
  end
end
