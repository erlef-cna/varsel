# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CveListLive do
  @moduledoc """
  The CVE list — one page for two audiences.

  Visitors (and non-POC users) get the public list of published CVEs with
  full-text search, paginated; the `:list_all` read policy scopes them to
  published records. POCs get the management console on top: the header band
  with pool sync/reserve actions, a reserved-pool summary panel above the
  table (collapsible, with per-ID inline reject), the paginated table of
  every active record (draft, publishing, published, pending_update), and an
  action-free rejected-IDs summary panel below it. Editing a record's JSON
  lives on `VarselWeb.VarselEditLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CveView, only: [best_cvss: 1, package_ref: 1]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

  alias Varsel.CVE
  alias Varsel.CVE.CveRecord

  require Ash.Query

  # States whose cve_json can be edited (:request_publish / :update `from` sets).
  @editable [:draft, :published, :pending_update]

  # The states the records table lists (reserved and rejected records live in
  # their own summary panels) — also the table's filter-scope order.
  @table_states [:draft, :publishing, :published, :pending_update]

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    poc? = poc?(socket.assigns.current_user)

    socket =
      socket
      |> assign(
        page_title: if(poc?, do: "CVE records", else: "Issued CVEs"),
        poc?: poc?,
        mitre_syncing?: false,
        query: "",
        filter: "all",
        record_counts: %{},
        pool_open?: false,
        rejected_open?: false,
        confirming_reject_id: nil
      )
      |> keep_records_live()

    socket = if poc?, do: socket |> keep_pool_live() |> keep_rejected_live(), else: socket

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
        do: Keyword.put(opts, :after_fetch, &assign_record_counts/2),
        else: opts

    keep_live(socket, :cve_records, &list_cve_records/2, opts)
  end

  # The filter counts always cover the whole table set, independent of the
  # current filter/search.
  defp assign_record_counts(_page, socket) do
    counts =
      [
        actor: socket.assigns.current_user,
        query:
          CveRecord
          |> Ash.Query.filter(state in ^@table_states)
          |> Ash.Query.select([:state])
      ]
      |> CVE.list_all_cve_records!()
      |> Enum.frequencies_by(& &1.state)

    assign(socket, :record_counts, counts)
  end

  # The reserved pool is its own live-kept, unpaginated collection — the
  # summary panel needs the whole pool (count, ID span, oldest date), not a
  # page of it.
  defp keep_pool_live(socket) do
    keep_live(socket, :pool, &list_pool/1, subscribe: "cve_record:all", results: :lose)
  end

  defp list_pool(socket) do
    CVE.list_all_cve_records!(
      actor: socket.assigns.current_user,
      query:
        CveRecord
        |> Ash.Query.filter(state == :reserved)
        |> Ash.Query.load([:cve_id, :reserved_at])
        |> Ash.Query.sort(reserved_at: :asc)
    )
  end

  # Rejected IDs get the same summary-panel treatment below the records
  # table (action-free — rejection is terminal).
  defp keep_rejected_live(socket) do
    keep_live(socket, :rejected, &list_rejected/1, subscribe: "cve_record:all", results: :lose)
  end

  defp list_rejected(socket) do
    CVE.list_all_cve_records!(
      actor: socket.assigns.current_user,
      query:
        CveRecord
        |> Ash.Query.filter(state == :rejected)
        |> Ash.Query.load([:cve_id])
        |> Ash.Query.sort(rejected_at: :asc)
    )
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

    socket =
      case socket.assigns.pool do
        [] ->
          put_flash(socket, :error, "No reserved IDs in the pool.")

        [record | _rest] ->
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

  def handle_event("toggle_pool", _params, socket) do
    {:noreply, assign(socket, pool_open?: not socket.assigns.pool_open?, confirming_reject_id: nil)}
  end

  def handle_event("toggle_rejected", _params, socket) do
    {:noreply, assign(socket, rejected_open?: not socket.assigns.rejected_open?)}
  end

  def handle_event("reject_prompt", %{"id" => record_id}, socket) do
    {:noreply, assign(socket, :confirming_reject_id, record_id)}
  end

  def handle_event("reject_cancel", _params, socket) do
    {:noreply, assign(socket, :confirming_reject_id, nil)}
  end

  def handle_event("reject", %{"id" => record_id}, socket) do
    actor = socket.assigns.current_user

    record =
      Enum.find(socket.assigns.pool, &(&1.id == record_id)) ||
        Enum.find(socket.assigns.cve_records.results, &(&1.id == record_id))

    reason =
      if record.state == :reserved,
        do: "Rejected from the reserved pool",
        else: "Rejected before publication"

    socket =
      case CVE.reject_cve_record(record, %{rejection_reason: reason}, actor: actor) do
        {:ok, rejected} ->
          socket
          |> assign(:confirming_reject_id, nil)
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

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :cve_records, target)}
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

  # Every active record — including :draft, which stays listed (and
  # editable) here as the manual escape hatch alongside the /cases flow.
  # Reserved and rejected records live in their own summary panels.
  defp records_query(filter, query) do
    CveRecord
    |> Ash.Query.load([:purls, :cve_json, :case])
    |> Ash.Query.filter(state in ^@table_states)
    |> filter_state(filter)
    |> filter_search(query)
  end

  defp filter_state(base, "all"), do: base

  defp filter_state(base, filter) do
    state = Enum.find(@table_states, &(to_string(&1) == filter)) || :none
    Ash.Query.filter(base, state == ^state)
  end

  # ID/title substring match plus the full-text search over the published
  # record bodies (draft rows may have no search vector and simply never
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

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  defp table_states, do: @table_states

  defp editable?(state), do: state in @editable

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")

  defp count_label(count, singular) when is_integer(count) do
    if count == 1, do: "1 #{singular}", else: "#{count} #{singular}s"
  end

  defp count_label(_count, singular), do: "#{singular}s"

  # A record's CVSS score, coerced to float for `severity_chip`, or nil when
  # unscored (reserved/draft/publishing rows have no cve_json yet).
  defp record_score(%{cve_json: nil}), do: nil

  defp record_score(%{cve_json: cve_json}) do
    case cve_json |> get_in(["containers", "cna"]) |> Kernel.||(%{}) |> best_cvss() do
      %{"baseScore" => score} -> score / 1
      nil -> nil
    end
  end

  defp pool_id_range([]), do: nil
  defp pool_id_range([only]), do: only.cve_id
  defp pool_id_range(records), do: "#{List.first(records).cve_id} … #{List.last(records).cve_id}"

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
      <:actions>
        <form id="cve-record-search" phx-change="search" phx-submit="search">
          <.console_search
            value={@query}
            placeholder={
              if @poc?, do: "Search records…", else: "Search by ID, title, package, description…"
            }
          />
        </form>
        <button
          :if={@poc?}
          class="btn btn-sm btn-eef-quiet"
          phx-click="sync_with_mitre"
          disabled={@mitre_syncing?}
        >
          {if @mitre_syncing?, do: "Syncing…", else: "Sync pool"}
        </button>
        <button :if={@poc?} class="btn btn-sm btn-eef" phx-click="reserve">
          Reserve a new one
        </button>
      </:actions>
    </.console_header>

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6">
      <.pool_panel
        :if={@poc?}
        pool={@pool}
        open?={@pool_open?}
        confirming_reject_id={@confirming_reject_id}
      />

      <div class="rounded-box border border-base-300 bg-base-200 overflow-hidden">
        <div
          :if={@poc?}
          class="flex flex-wrap items-center gap-3.5 px-4 py-2.5 border-b border-base-300 text-[0.76rem] text-base-content/60"
        >
          <.scope_button
            active={@filter}
            value="all"
            label="All"
            count={@record_counts |> Map.values() |> Enum.sum()}
          />
          <.scope_button
            :for={state <- table_states()}
            active={@filter}
            value={to_string(state)}
            label={Phoenix.Naming.humanize(state)}
            count={Map.get(@record_counts, state, 0)}
          />
        </div>
        <div
          :if={not @poc?}
          class="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-base-300"
        >
          <span class="text-sm text-base-content/70 tabular-nums">
            {count_label(@cve_records.count, "CVE")}
          </span>
        </div>

        <div class="overflow-x-auto">
          <table class="table">
            <thead>
              <tr>
                <th>CVE ID</th>
                <th>Title</th>
                <th>Packages</th>
                <th>Severity</th>
                <th :if={@poc?}>State</th>
                <th>Published</th>
                <th>Updated</th>
                <th :if={@poc?}></th>
              </tr>
            </thead>
            <tbody>
              <tr :for={record <- @cve_records.results} class="hover:bg-base-300/40">
                <td class="font-mono text-xs whitespace-nowrap text-base-content/60">
                  {record.cve_id || "—"}
                </td>
                <td class="max-w-md">
                  <.link
                    :if={record.state == :published}
                    navigate={~p"/cves/#{record.cve_id}"}
                    class="link link-hover font-semibold"
                  >
                    {record.title || record.cve_id}
                  </.link>
                  <span
                    :if={record.state != :published}
                    class={record.state == :publishing && "font-semibold"}
                  >
                    {record.title || "—"}
                  </span>
                </td>
                <td>
                  <div :for={purl <- record.purls || []} class="text-sm">
                    <.package_ref entry={%{"packageURL" => purl}} link={true} />
                  </div>
                </td>
                <td>
                  <.severity_chip score={record_score(record)} />
                </td>
                <td :if={@poc?}>
                  <.record_state_cell record={record} />
                </td>
                <td class="whitespace-nowrap tabular-nums">
                  {format_dt(record.date_published)}
                </td>
                <td class="whitespace-nowrap tabular-nums">
                  {format_dt(record.date_updated)}
                </td>
                <td :if={@poc?}>
                  <div
                    :if={@confirming_reject_id != record.id}
                    class="flex items-center gap-4 justify-end whitespace-nowrap"
                  >
                    <.link
                      :if={editable?(record.state)}
                      navigate={~p"/cves/manage/#{record.id}"}
                      class="link link-hover text-primary text-sm font-medium"
                    >
                      Edit
                    </.link>
                    <button
                      :if={record.state == :draft}
                      type="button"
                      class="text-xs font-semibold text-error/85"
                      phx-click="reject_prompt"
                      phx-value-id={record.id}
                    >
                      Reject
                    </button>
                  </div>
                  <div
                    :if={@confirming_reject_id == record.id}
                    class="flex items-center gap-2 justify-end whitespace-nowrap rounded-md bg-error/10 px-2 py-1"
                  >
                    <span class="text-xs text-base-content/60">
                      reject at MITRE? can't be reused
                    </span>
                    <button
                      type="button"
                      class="btn btn-error btn-xs"
                      phx-click="reject"
                      phx-value-id={record.id}
                    >
                      Reject
                    </button>
                    <button
                      type="button"
                      class="btn btn-ghost btn-xs border border-base-300"
                      phx-click="reject_cancel"
                    >
                      Cancel
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

        <.jump_pagination :if={@poc?} page={@cve_records} noun="record" />

        <div
          :if={
            not @poc? and is_integer(@cve_records.count) and @cve_records.count > @cve_records.limit
          }
          class="flex flex-wrap items-center justify-between gap-3 px-4 py-2 border-t border-base-300"
        >
          <span class="text-xs text-base-content/60">{@cve_records.limit} per page</span>
          <.pagination page={@cve_records} event="paginate" />
        </div>
      </div>

      <.rejected_panel :if={@poc?} rejected={@rejected} open?={@rejected_open?} />

      <p class="mt-6 text-sm text-base-content/60">
        Machine-readable: <a href={~p"/cves/index.json"} class="link">CVE index (JSON)</a>
        · <a href={~p"/osv/all.json"} class="link">OSV feed (JSON)</a>
        · <a href={~p"/feed.atom"} class="link">Atom</a>
        · <a href={~p"/feed.rss"} class="link">RSS</a>
      </p>
    </div>
    """
  end

  attr :active, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true

  # A table filter scope, styled like the cases archive scope strip: label +
  # count, active = ink + accent count. A scope is a filter, not a resort.
  defp scope_button(assigns) do
    ~H"""
    <button
      type="button"
      phx-click="filter"
      phx-value-filter={@value}
      class={["cursor-pointer", @active == @value && "font-bold text-base-content"]}
    >
      {@label}
      <span class={[
        "font-semibold tabular-nums ml-1",
        if(@active == @value, do: "text-primary", else: "text-base-content/50")
      ]}>
        {@count}
      </span>
    </button>
    """
  end

  attr :record, :any, required: true

  defp record_state_cell(assigns) do
    ~H"""
    <span :if={@record.state == :draft and @record.case} class="text-warning text-sm">
      ● Draft · <.link navigate={~p"/cases/#{@record.case.id}"} class="link link-hover">case →</.link>
    </span>
    <span :if={@record.state == :draft and !@record.case} class="text-warning text-sm">
      ● Draft
    </span>
    <span :if={@record.state == :published and @record.case} class="text-base-content/60 text-sm">
      ● Published ·
      <.link navigate={~p"/cases/#{@record.case.id}"} class="link link-hover">case →</.link>
    </span>
    <span :if={@record.state == :published and !@record.case} class="text-base-content/60 text-sm">
      ● Published
    </span>
    <span :if={@record.state == :pending_update and @record.case} class="text-warning text-sm">
      ● Pending update ·
      <.link navigate={~p"/cases/#{@record.case.id}"} class="link link-hover">case →</.link>
    </span>
    <span :if={@record.state == :pending_update and !@record.case} class="text-warning text-sm">
      ● Pending update
    </span>
    <span :if={@record.state == :publishing and @record.case} class="text-info text-sm">
      ● Publishing ·
      <.link navigate={~p"/cases/#{@record.case.id}"} class="link link-hover">case →</.link>
    </span>
    <span :if={@record.state == :publishing and !@record.case} class="text-info text-sm">
      ● Publishing
    </span>
    """
  end

  attr :pool, :list, required: true
  attr :open?, :boolean, required: true
  attr :confirming_reject_id, :string, default: nil

  defp pool_panel(assigns) do
    records = assigns.pool
    oldest = List.first(records)

    assigns =
      assign(assigns,
        records: records,
        count: length(records),
        id_range: pool_id_range(records),
        oldest: oldest
      )

    ~H"""
    <div class="rounded-box border border-base-300 bg-base-200 mb-4">
      <div class="flex flex-wrap items-center gap-3 px-4 py-2.5">
        <span class="flex items-center gap-2 text-[0.7rem] font-bold uppercase tracking-wider text-base-content/60">
          <span class="size-1.5 rounded-full bg-base-content/30 shrink-0"></span> Reserved pool
        </span>
        <span class="text-sm font-bold tabular-nums">{count_label(@count, "ID")}</span>
        <span :if={@id_range} class="font-mono text-xs text-base-content/60">{@id_range}</span>
        <span :if={@oldest} class="text-xs text-base-content/50">
          oldest reserved {format_dt(@oldest.reserved_at)}
        </span>
        <button
          type="button"
          class="btn btn-ghost btn-xs ml-auto"
          phx-click="toggle_pool"
          disabled={@count == 0}
        >
          {if @open?, do: "Hide IDs ▴", else: "Show IDs ▾"}
        </button>
      </div>

      <div
        :if={@open? and @count > 0}
        id="pool-ids"
        class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 px-4 pb-3 pt-1 border-t border-base-300"
      >
        <.pool_row
          :for={record <- @records}
          record={record}
          confirming?={@confirming_reject_id == record.id}
        />
      </div>
    </div>
    """
  end

  attr :record, :any, required: true
  attr :confirming?, :boolean, required: true

  defp pool_row(assigns) do
    ~H"""
    <div
      :if={not @confirming?}
      class="flex items-center gap-3 py-1 text-sm"
    >
      <span class="font-mono text-xs text-base-content/60">{@record.cve_id}</span>
      <span class="text-xs text-base-content/50">reserved {format_dt(@record.reserved_at)}</span>
      <button
        type="button"
        class="ml-auto text-xs font-semibold text-error/85"
        phx-click="reject_prompt"
        phx-value-id={@record.id}
      >
        Reject
      </button>
    </div>
    <div
      :if={@confirming?}
      class="flex items-center gap-3 py-1 px-2 -mx-2 my-0.5 rounded-md text-sm bg-error/10"
    >
      <span class="font-mono text-xs text-base-content/60">{@record.cve_id}</span>
      <span class="text-xs text-base-content/60">reject at MITRE? can't be reused</span>
      <div class="ml-auto flex items-center gap-2 shrink-0">
        <button
          type="button"
          class="btn btn-error btn-xs"
          phx-click="reject"
          phx-value-id={@record.id}
        >
          Reject
        </button>
        <button
          type="button"
          class="btn btn-ghost btn-xs border border-base-300"
          phx-click="reject_cancel"
        >
          Cancel
        </button>
      </div>
    </div>
    """
  end

  attr :rejected, :list, required: true
  attr :open?, :boolean, required: true

  # Same summary-panel treatment as the reserved pool, but action-free:
  # rejection is terminal, so the disclosure only lists the IDs.
  defp rejected_panel(assigns) do
    records = assigns.rejected
    latest = List.last(records)

    assigns =
      assign(assigns,
        records: records,
        count: length(records),
        id_range: pool_id_range(records),
        latest: latest
      )

    ~H"""
    <div :if={@count > 0} class="rounded-box border border-base-300 bg-base-200 mt-4">
      <div class="flex flex-wrap items-center gap-3 px-4 py-2.5">
        <span class="flex items-center gap-2 text-[0.7rem] font-bold uppercase tracking-wider text-base-content/60">
          <span class="size-1.5 rounded-full bg-error/60 shrink-0"></span> Rejected
        </span>
        <span class="text-sm font-bold tabular-nums">{count_label(@count, "ID")}</span>
        <span :if={@id_range} class="font-mono text-xs text-base-content/60">{@id_range}</span>
        <span :if={@latest} class="text-xs text-base-content/50">
          last rejected {format_dt(@latest.rejected_at)}
        </span>
        <button type="button" class="btn btn-ghost btn-xs ml-auto" phx-click="toggle_rejected">
          {if @open?, do: "Hide IDs ▴", else: "Show IDs ▾"}
        </button>
      </div>

      <div
        :if={@open?}
        id="rejected-ids"
        class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 px-4 pb-3 pt-1 border-t border-base-300"
      >
        <div :for={record <- @records} class="flex items-center gap-3 py-1 text-sm">
          <span class="font-mono text-xs text-base-content/60">{record.cve_id}</span>
          <span class="text-xs text-base-content/50">rejected {format_dt(record.rejected_at)}</span>
        </div>
      </div>
    </div>
    """
  end
end
