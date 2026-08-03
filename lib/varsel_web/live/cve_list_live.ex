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
  table (collapsible, with per-ID inline withhold and reject), the paginated
  table of every active record (draft, publishing, published, pending_update),
  and action-free withheld- and rejected-IDs summary panels below it. Editing
  a record's JSON lives on `VarselWeb.VarselEditLive`.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CveView, only: [package_display_name: 1]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

  alias Varsel.Cases
  alias Varsel.Cases.Validations.CveRecordAdoptable
  alias Varsel.CVE
  alias Varsel.CVE.CveRecord
  alias Varsel.Types.CVSS

  require Ash.Query

  # The states the records table lists (reserved, withheld and rejected
  # records live in their own summary panels) — also the table's filter-scope
  # order.
  @table_states [:draft, :publishing, :published, :pending_update]

  @adoptable_states CveRecordAdoptable.adoptable_states()

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    # One page, two readings: the public list of what has been issued, and the
    # console the same list becomes for whoever works the pool. Which one you
    # get follows from whether reserving an ID is something you may do —
    # everything the console adds hangs off that pool.
    console? = Ash.can?({CveRecord, :assign}, socket.assigns.current_user)

    socket =
      socket
      |> assign(
        page_title: if(console?, do: "CVE records", else: "Issued CVEs"),
        console?: console?,
        # Row-independent half of the adoption affordance; the per-row half is
        # adoptable?/1 (see there for why it is split).
        may_adopt?: Ash.can?({Cases.Case, :adopt_cve_record}, socket.assigns.current_user),
        mitre_syncing?: false,
        query: "",
        filter: "all",
        record_counts: %{},
        pool_open?: false,
        withheld_open?: false,
        rejected_open?: false,
        confirming_reject_id: nil,
        withholding_id: nil
      )
      |> keep_records_live()

    socket =
      if console?,
        do: socket |> keep_pool_live() |> keep_withheld_live() |> keep_rejected_live(),
        else: socket

    {:ok, socket}
  end

  # (Re)binds the paginated record page to the current filter/search. On a
  # narrowing change the subscription is torn down first so keep_live can
  # re-subscribe without stacking duplicate PubSub deliveries.
  defp keep_records_live(socket) do
    socket.endpoint.unsubscribe("cve_record:all")

    opts = [subscribe: "cve_record:all", results: :lose]

    opts =
      if socket.assigns.console?,
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
        |> Ash.Query.select([:id, :state, :version])
    )
  end

  # Withheld IDs get the same summary-panel treatment: they are out of the
  # pool but not terminal, so the panel keeps the reject action — the only
  # way out of the hold that is ours to take (the other is MITRE publishing
  # the ID, which the sync picks up on its own).
  defp keep_withheld_live(socket) do
    keep_live(socket, :withheld, &list_withheld/1, subscribe: "cve_record:all", results: :lose)
  end

  defp list_withheld(socket) do
    CVE.list_all_cve_records!(
      actor: socket.assigns.current_user,
      query:
        CveRecord
        |> Ash.Query.filter(state == :withheld)
        |> Ash.Query.load([:cve_id, :reserved_at])
        |> Ash.Query.sort(withheld_at: :asc)
        |> Ash.Query.select([:id, :state, :version, :withheld_at, :withhold_reason])
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
        |> Ash.Query.load([:cve_id, :rejected_at])
        |> Ash.Query.sort(rejected_at: :asc)
        |> Ash.Query.select([:id, :state, :version])
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
        |> CVE.sync_cve_record_from_mitre!(%{},
          actor: actor,
          bulk_options: [
            notify?: true,
            return_errors?: true,
            strategy: :stream,
            allow_stream_with: :full_read
          ]
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
    {:noreply,
     assign(socket,
       pool_open?: not socket.assigns.pool_open?,
       confirming_reject_id: nil,
       withholding_id: nil
     )}
  end

  def handle_event("toggle_withheld", _params, socket) do
    {:noreply, assign(socket, withheld_open?: not socket.assigns.withheld_open?, confirming_reject_id: nil)}
  end

  def handle_event("toggle_rejected", _params, socket) do
    {:noreply, assign(socket, rejected_open?: not socket.assigns.rejected_open?)}
  end

  # Withholding asks for a reason the way rejection does — an ID held for
  # something outside this system is only legible later if it says what for.
  def handle_event("withhold_prompt", %{"id" => record_id}, socket) do
    {:noreply, assign(socket, withholding_id: record_id, confirming_reject_id: nil)}
  end

  def handle_event("withhold_cancel", _params, socket) do
    {:noreply, assign(socket, :withholding_id, nil)}
  end

  def handle_event("withhold", params, socket) do
    actor = socket.assigns.current_user
    record = Enum.find(socket.assigns.pool, &(&1.id == params["record_id"]))
    reason = params["reason"] |> to_string() |> String.trim()

    socket =
      case CVE.withhold_cve_record(record, %{withhold_reason: reason}, actor: actor) do
        {:ok, withheld} ->
          socket
          |> assign(:withholding_id, nil)
          |> put_flash(:info, "Withheld #{withheld.cve_id} from the pool.")

        {:error, error} ->
          put_flash(socket, :error, "Could not withhold: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  # The withheld panel's undo: the ID returns as a draft, not to the open
  # pool, so releasing it is a decision to work it here rather than a
  # candidate for the next auto-assignment.
  def handle_event("release", %{"id" => record_id}, socket) do
    actor = socket.assigns.current_user
    record = Enum.find(socket.assigns.withheld, &(&1.id == record_id))

    socket =
      case CVE.assign_cve_record(record, %{}, actor: actor) do
        {:ok, drafted} ->
          put_flash(socket, :info, "Released #{drafted.cve_id} — now a draft.")

        {:error, error} ->
          put_flash(socket, :error, "Could not release: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  def handle_event("adopt", %{"id" => record_id}, socket) do
    actor = socket.assigns.current_user

    case Cases.adopt_cve_record(%{cve_record_id: record_id}, actor: actor) do
      {:ok, case_record} ->
        {:noreply, push_navigate(socket, to: ~p"/cases/#{case_record.id}")}

      {:error, error} ->
        {:noreply, put_flash(socket, :error, "Could not open a case: #{errors_to_string(error)}")}
    end
  end

  def handle_event("reject_prompt", %{"id" => record_id}, socket) do
    {:noreply, assign(socket, :confirming_reject_id, record_id)}
  end

  def handle_event("reject_cancel", _params, socket) do
    {:noreply, assign(socket, :confirming_reject_id, nil)}
  end

  # The pool confirm clicks through with phx-value-id; the table confirm
  # submits its P4 reason form, whose hidden field is "record_id" (an input
  # named "id" would override the form element's DOM id).
  def handle_event("reject", params, socket) do
    actor = socket.assigns.current_user
    record_id = params["id"] || params["record_id"]

    record =
      Enum.find(socket.assigns.pool, &(&1.id == record_id)) ||
        Enum.find(socket.assigns.withheld, &(&1.id == record_id)) ||
        Enum.find(socket.assigns.cve_records.results, &(&1.id == record_id))

    reason = reject_reason(record, params["reason"])

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
      query: records_query(socket.assigns.filter, socket.assigns.query, socket.assigns.current_user),
      page: page_opts || [count: true, offset: 0]
    )
  end

  # Every active record — including :draft, which stays listed (and
  # editable) here as the manual escape hatch alongside the /cases flow.
  # Reserved and rejected records live in their own summary panels.
  defp records_query(filter, query, actor) do
    base_loads = [:purls, :cvss, :title]

    # The case a record backs is only loadable by someone who may read cases;
    # for everyone else the row stands on its own.
    loads =
      if Ash.can?({Varsel.Cases.Case, :read}, actor),
        do: [:case | base_loads],
        else: base_loads

    CveRecord
    |> Ash.Query.load(loads)
    |> Ash.Query.filter(state in ^@table_states)
    |> Ash.Query.select([:id, :state, :version])
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

  # P4: the pool confirm sends no "reason" param and keeps its fixed copy —
  # an unused reserved ID has no story worth prompting for. The table
  # confirm's reason input is prefilled with (and defaults to, if blanked)
  # the same fixed copy it replaces, so accepting it unedited behaves
  # exactly as built.
  defp reject_reason(record, reason) do
    case reason && String.trim(reason) do
      "" -> default_reject_reason(record)
      nil -> default_reject_reason(record)
      trimmed -> trimmed
    end
  end

  defp default_reject_reason(%{state: :reserved}), do: "Rejected from the reserved pool"
  defp default_reject_reason(%{state: :withheld}), do: "Discarded while withheld from the pool"
  defp default_reject_reason(_record), do: "Rejected before publication"

  defp table_states, do: @table_states

  # The edit page writes through whichever action the record's state allows —
  # `:request_publish` for a draft, `:update` once published — so offering the
  # link is a question of whether either of them would run.
  defp editable?(actor, record) do
    CVE.can_request_publish_cve_record?(actor, record, %{}) or
      CVE.can_update_cve_record?(actor, record, %{})
  end

  # Whether this record is still waiting for a case.
  #
  # Asked in two halves so the table does not run a query per row: whether the
  # actor may adopt *anything* is a policy question with no particular record
  # in it (resolved once in mount), and whether this record is adoptable is
  # answered by the row itself — the same two conditions
  # `Varsel.Cases.Validations.CveRecordAdoptable` enforces, which stays the
  # authority when the button is actually pressed.
  #
  # `:case` is only loaded for an actor who may read cases, so an unloaded
  # value means "not for you to know", not "no case" (see records_query/3).
  defp adoptable?(record) do
    match?(nil, Map.get(record, :case)) and record.state in @adoptable_states
  end

  # P3's search feedback reads as a sentence ("14 match “ssh”"), so the
  # verb agrees with the count rather than pluralizing a noun.
  defp match_summary(count, query) do
    count = if is_integer(count), do: count, else: 0
    verb = if count == 1, do: "matches", else: "match"
    ~s(#{count} #{verb} “#{String.trim(query)}”)
  end

  defp record_score(%{cvss: nil}), do: nil
  defp record_score(%{cvss: %CVSS{score: score}}), do: score

  defp pool_id_range([]), do: nil
  defp pool_id_range([only]), do: only.cve_id

  # The span abbreviates its right end ("CVE-2026-20041 … 20052") when both
  # ends share a year — the prefix would repeat verbatim.
  defp pool_id_range(records) do
    first = List.first(records).cve_id
    last = List.last(records).cve_id

    case {String.split(first, "-"), String.split(last, "-")} do
      {["CVE", year, _serial], ["CVE", year, serial]} -> "#{first} … #{serial}"
      _other -> "#{first} … #{last}"
    end
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <.page_header>
      <:eyebrow>{if @console?, do: "CNA Console", else: "EEF CNA"}</:eyebrow>
      <:title>{if @console?, do: "CVE records", else: "Issued CVEs"}</:title>
      <:subtitle :if={@console?}>Reserve, draft, publish, and reject CVE records.</:subtitle>
      <:subtitle :if={not @console?}>
        Vulnerabilities assigned and published by the EEF CNA.
      </:subtitle>
      <:actions>
        <.console_search
          id="cve-record-search"
          value={@query}
          placeholder={
            if @console?, do: "Search records…", else: "Search by ID, title, package, description…"
          }
        />
        <button
          :if={Ash.can?({CveRecord, :import_from_mitre}, @current_user)}
          class="btn btn-sm btn-eef-quiet"
          phx-click="sync_with_mitre"
          disabled={@mitre_syncing?}
        >
          {if @mitre_syncing?, do: "Syncing…", else: "Sync pool"}
        </button>
        <button
          :if={Ash.can?({CveRecord, :assign}, @current_user)}
          class="btn btn-sm btn-eef"
          phx-click="reserve"
        >
          Reserve a new one
        </button>
      </:actions>
    </.page_header>

    <.page_container>
      <.pool_panel
        :if={@console?}
        pool={@pool}
        open?={@pool_open?}
        confirming_reject_id={@confirming_reject_id}
        withholding_id={@withholding_id}
        current_user={@current_user}
      />

      <.list_card>
        <:tabs :if={@console?}>
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
        </:tabs>
        <:note :if={@console? and String.trim(@query) != ""}>
          <span class="font-semibold text-info tabular-nums">
            {match_summary(@cve_records.count, @query)}
          </span>
        </:note>
        <:note :if={not @console?}>
          Machine-readable: <.link href={~p"/cves/index.json"} class="link">JSON</.link>
          · <.link href={~p"/osv/all.json"} class="link">OSV</.link>
          · <.link href={~p"/feed.atom"} class="link">Atom</.link>
          · <.link href={~p"/feed.rss"} class="link">RSS</.link>
        </:note>

        <div class="overflow-x-auto">
          <table class="table table-fixed min-w-[60rem]">
            <thead>
              <tr>
                <th class="w-32">CVE ID</th>
                <th>Title</th>
                <th class="w-56">Packages</th>
                <th class="w-20">Severity</th>
                <th :if={@console?} class="w-32">State</th>
                <th class="w-24">Published</th>
                <th :if={@console?} class="w-16"></th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={record <- @cve_records.results}
                class={["group hover:bg-base-300/40", not @console? && "cursor-pointer"]}
                phx-click={not @console? && JS.navigate(~p"/cves/#{record.cve_id <> ".html"}")}
              >
                <td class="font-mono text-xs whitespace-nowrap text-base-content/60">
                  {record.cve_id || "—"}
                </td>
                <td>
                  <.link
                    :if={record.state == :published and @console?}
                    href={~p"/cves/#{record.cve_id <> ".html"}"}
                    class="link link-hover font-semibold"
                  >
                    {record.title || record.cve_id}
                  </.link>
                  <span
                    :if={not @console? and record.state == :published}
                    class="font-semibold group-hover:text-primary"
                  >
                    {record.title || record.cve_id}
                  </span>
                  <span
                    :if={@console? and record.state != :published}
                    class={record.state == :publishing && "font-semibold"}
                  >
                    {record.title || "—"}
                  </span>
                </td>
                <%!-- The empty JS command shields the nested hex.pm links
                      from the row's click-through: LiveView only executes
                      the binding closest to the click target, and inline
                      handlers are out (CSP). --%>
                <td phx-click={%JS{}}>
                  <div :for={purl <- record.purls || []} class="text-xs break-all">
                    <.package_display_name purl={purl} link={true} />
                  </div>
                </td>
                <td>
                  <.severity_chip score={record_score(record)} />
                </td>
                <td :if={@console?}>
                  <.record_state_cell record={record} may_adopt?={@may_adopt?} />
                </td>
                <td class="whitespace-nowrap tabular-nums text-xs">
                  {format_date(record.date_published)}
                </td>
                <td :if={@console?} class="relative text-right">
                  <div class="flex flex-col items-end gap-0.5">
                    <.link
                      :if={editable?(@current_user, record)}
                      navigate={~p"/cves/manage/#{record.id}"}
                      class="link link-hover text-primary text-sm font-medium"
                    >
                      Edit
                    </.link>
                    <button
                      :if={
                        CVE.can_reject_cve_record?(@current_user, record) and
                          @confirming_reject_id != record.id
                      }
                      type="button"
                      class="text-xs font-semibold text-error/85"
                      phx-click="reject_prompt"
                      phx-value-id={record.id}
                    >
                      Reject
                    </button>
                  </div>
                  <%!-- Floating confirm: anchored to the cell so narrow
                        action columns never clip the consequence line. --%>
                  <form
                    :if={@confirming_reject_id == record.id}
                    phx-submit="reject"
                    phx-click-away="reject_cancel"
                    phx-window-keydown="reject_cancel"
                    phx-key="escape"
                    class="absolute right-0 top-1/2 -translate-y-1/2 z-10 flex w-[min(26rem,calc(100vw-3rem))] flex-wrap items-center justify-end gap-2 rounded-md border border-error/30 bg-base-200 px-3 py-2 shadow-lg"
                  >
                    <input type="hidden" name="record_id" value={record.id} />
                    <span class="text-xs text-base-content/60 basis-full text-right">
                      reject at MITRE? can't be reused — the reason becomes part of the record
                    </span>
                    <input
                      type="text"
                      name="reason"
                      value={default_reject_reason(record)}
                      autofocus
                      class="input input-xs flex-1 min-w-56 border-error/30"
                    />
                    <button type="submit" class="btn btn-error btn-xs">
                      Reject
                    </button>
                    <button
                      type="button"
                      class="btn btn-ghost btn-xs border border-base-300"
                      phx-click="reject_cancel"
                    >
                      Cancel
                    </button>
                  </form>
                </td>
              </tr>
            </tbody>
          </table>

          <.empty_state :if={@cve_records.results == []}>
            No CVEs match your search.
          </.empty_state>
        </div>

        <:footer :if={paged?(@cve_records)}>
          <.pagination page={@cve_records} noun={if @console?, do: "record", else: "CVE"} />
        </:footer>
      </.list_card>

      <.withheld_panel
        :if={@console?}
        withheld={@withheld}
        open?={@withheld_open?}
        confirming_reject_id={@confirming_reject_id}
        current_user={@current_user}
      />

      <.rejected_panel :if={@console?} rejected={@rejected} open?={@rejected_open?} />

      <p :if={@console?} class="mt-6 text-sm text-base-content/60">
        Machine-readable: <.link href={~p"/cves/index.json"} class="link">CVE index (JSON)</.link>
        · <.link href={~p"/osv/all.json"} class="link">OSV feed (JSON)</.link>
        · <.link href={~p"/feed.atom"} class="link">Atom</.link>
        · <.link href={~p"/feed.rss"} class="link">RSS</.link>
      </p>
    </.page_container>
    """
  end

  attr :active, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true

  # A scope is a filter, not a resort: the table narrows in place, so the
  # scope lives in the view rather than the URL and this is a button.
  defp scope_button(assigns) do
    assigns = assign(assigns, :active?, assigns.active == assigns.value)

    ~H"""
    <button type="button" phx-click="filter" phx-value-filter={@value}>
      <.scope_tab active?={@active?} label={@label} count={@count} />
    </button>
    """
  end

  attr :record, :any, required: true
  attr :may_adopt?, :boolean, required: true

  # P1: state text (dot + label, state-toned, non-interactive) on the left,
  # a quiet bordered case chip pinned to the cell's right edge when an
  # owning case exists — one hover treatment regardless of state tone,
  # instead of the state color bleeding into an appended "· case →" link.
  #
  # A record with no case gets the chip's counterpart in the same slot: the
  # cell says either where this record's case is or how to give it one, and
  # never both. That keeps the case relationship in one column instead of
  # splitting it between here and the actions cell, where a third stacked verb
  # crowds the row and the label collides with the date.
  defp record_state_cell(assigns) do
    ~H"""
    <div class="flex flex-col items-start gap-1">
      <.state dot={state_dot_class(@record.state)} class={state_text_class(@record.state)}>
        {Phoenix.Naming.humanize(@record.state)}
      </.state>
      <.link
        :if={match?(%Varsel.Cases.Case{}, @record.case)}
        navigate={~p"/cases/#{@record.case.id}"}
        class={chip_class()}
      >
        case <span class="text-[0.7rem] leading-none">→</span>
      </.link>
      <button
        :if={@may_adopt? and adoptable?(@record)}
        type="button"
        class={chip_class()}
        phx-click="adopt"
        phx-value-id={@record.id}
      >
        manage as case
      </button>
    </div>
    """
  end

  # The quiet bordered chip both case affordances wear: one hover treatment,
  # unaffected by the state tone beside it.
  defp chip_class do
    "inline-flex items-center gap-[0.32rem] text-[0.67rem] font-semibold text-base-content/60 " <>
      "bg-base-100 border border-base-300 rounded-[5px] px-[0.45rem] py-[0.07rem] whitespace-nowrap " <>
      "transition-colors hover:text-primary hover:border-primary/60 hover:bg-primary/10"
  end

  defp state_dot_class(:draft), do: "bg-warning"
  defp state_dot_class(:pending_update), do: "bg-warning"
  defp state_dot_class(:publishing), do: "bg-info"
  defp state_dot_class(:published), do: "bg-base-content/40"
  defp state_dot_class(:withheld), do: "bg-base-content/30"
  defp state_dot_class(_state), do: "bg-base-content/30"

  defp state_text_class(:draft), do: "text-warning text-sm"
  defp state_text_class(:pending_update), do: "text-warning text-sm"
  defp state_text_class(:publishing), do: "text-info text-sm"
  defp state_text_class(:published), do: "text-base-content/60 text-sm"
  defp state_text_class(_state), do: "text-base-content/60 text-sm"

  attr :pool, :list, required: true
  attr :open?, :boolean, required: true
  attr :confirming_reject_id, :string, default: nil
  attr :withholding_id, :string, default: nil
  attr :current_user, :any, required: true

  # P2: count joins the label ("Reserved pool 12", no redundant "IDs"), the
  # facts become labeled pairs behind hairline separators (span, oldest),
  # and the oldest reservation gets the pipeline's amber staleness treatment
  # once it crosses @pool_stale_after — the pool's one "act on this" signal.
  defp pool_panel(assigns) do
    records = assigns.pool
    oldest = List.first(records)

    assigns =
      assign(assigns,
        records: records,
        count: length(records),
        id_range: pool_id_range(records),
        oldest: oldest,
        oldest_stale?: oldest && pool_stale?(oldest.reserved_at)
      )

    ~H"""
    <.summary_panel
      label="Reserved pool"
      dot="bg-base-content/30"
      count={@count}
      open?={@open?}
      toggle="toggle_pool"
      records_id="pool-ids"
      class="mb-4"
    >
      <:fact :if={@id_range} label="span" value={@id_range} mono?={true} />
      <:fact
        :if={@oldest}
        label="oldest"
        value={"#{format_date(@oldest.reserved_at)} · #{pool_age_days(@oldest.reserved_at)} d"}
        warn?={@oldest_stale?}
      />
      <.pool_row
        :for={record <- @records}
        record={record}
        confirming?={@confirming_reject_id == record.id}
        withholding?={@withholding_id == record.id}
        can_reject?={CVE.can_reject_cve_record?(@current_user, record)}
        can_withhold?={CVE.can_withhold_cve_record?(@current_user, record, %{})}
      />
    </.summary_panel>
    """
  end

  # The pool's staleness threshold (~30 days) — same "act on this" language
  # as the pipeline board's per-lane card ages, applied to the oldest
  # reservation's wait time.
  @pool_stale_after_days 30

  defp pool_age_days(%DateTime{} = reserved_at) do
    DateTime.diff(DateTime.utc_now(), reserved_at, :day)
  end

  defp pool_stale?(%DateTime{} = reserved_at), do: pool_age_days(reserved_at) >= @pool_stale_after_days

  attr :record, :any, required: true
  attr :confirming?, :boolean, required: true
  attr :withholding?, :boolean, required: true
  attr :can_reject?, :boolean, required: true
  attr :can_withhold?, :boolean, required: true

  defp pool_row(assigns) do
    ~H"""
    <div
      :if={not @confirming? and not @withholding?}
      class="grid grid-cols-[10rem_1fr_auto] items-center gap-3 py-1 text-sm"
    >
      <span class="font-mono text-xs text-base-content/60">{@record.cve_id}</span>
      <span class="text-xs text-base-content/50 tabular-nums">
        reserved {format_date(@record.reserved_at)}
      </span>
      <div class="flex items-center gap-3">
        <%!-- Withhold reads before Reject: it is the reversible one, and
              putting the destructive action last keeps the pool row's
              gradient of consequence going left to right. --%>
        <button
          :if={@can_withhold?}
          type="button"
          class="text-xs font-semibold text-base-content/60"
          phx-click="withhold_prompt"
          phx-value-id={@record.id}
        >
          Withhold
        </button>
        <button
          :if={@can_reject?}
          type="button"
          class="text-xs font-semibold text-error/85"
          phx-click="reject_prompt"
          phx-value-id={@record.id}
        >
          Reject
        </button>
      </div>
    </div>
    <form
      :if={@withholding?}
      phx-submit="withhold"
      phx-window-keydown="withhold_cancel"
      phx-key="escape"
      class="flex flex-wrap items-center gap-2 py-1 px-2 -mx-2 my-0.5 rounded-md text-sm bg-base-300/40"
    >
      <input type="hidden" name="record_id" value={@record.id} />
      <span class="font-mono text-xs text-base-content/60">{@record.cve_id}</span>
      <span class="text-xs text-base-content/60">held for what?</span>
      <input
        type="text"
        name="reason"
        value=""
        placeholder="e.g. reserved in the old management system"
        required
        autofocus
        class="input input-xs flex-1 min-w-56"
      />
      <div class="ml-auto flex items-center gap-2 shrink-0">
        <button type="submit" class="btn btn-neutral btn-xs">Withhold</button>
        <button
          type="button"
          class="btn btn-ghost btn-xs border border-base-300"
          phx-click="withhold_cancel"
        >
          Cancel
        </button>
      </div>
    </form>
    <div
      :if={@confirming?}
      phx-window-keydown="reject_cancel"
      phx-key="escape"
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

  attr :withheld, :list, required: true
  attr :open?, :boolean, required: true
  attr :confirming_reject_id, :string, default: nil
  attr :current_user, :any, required: true

  # Sits below the table rather than above it: withheld IDs are the pool's
  # backwater, not work in progress. Each row carries the reason it is held,
  # which is the only thing that makes the hold reviewable months later.
  defp withheld_panel(assigns) do
    records = assigns.withheld

    assigns =
      assign(assigns,
        records: records,
        count: length(records),
        id_range: pool_id_range(records)
      )

    ~H"""
    <.summary_panel
      :if={@count > 0}
      id="withheld-panel"
      label="Withheld"
      dot="bg-base-content/30"
      count={@count}
      open?={@open?}
      toggle="toggle_withheld"
      records_id="withheld-ids"
      class="mt-4"
    >
      <:fact :if={@id_range} label="span" value={@id_range} mono?={true} />
      <div
        :for={record <- @records}
        class="grid grid-cols-[10rem_1fr_auto] items-center gap-3 py-1 text-sm"
      >
        <span class="font-mono text-xs text-base-content/60">{record.cve_id}</span>
        <span class="text-xs text-base-content/50">
          {record.withhold_reason}
          <span class="tabular-nums text-base-content/40">
            · withheld {format_date(record.withheld_at)}
          </span>
        </span>
        <div :if={@confirming_reject_id != record.id} class="flex items-center gap-3">
          <%!-- Releasing is the deliberate undo of a hold: the ID comes back
                as a draft rather than to the open pool, so it stays out of
                anything that auto-picks. --%>
          <button
            :if={CVE.can_assign_cve_record?(@current_user, record, %{})}
            type="button"
            class="text-xs font-semibold text-base-content/60"
            phx-click="release"
            phx-value-id={record.id}
          >
            Release
          </button>
          <button
            :if={CVE.can_reject_cve_record?(@current_user, record)}
            type="button"
            class="text-xs font-semibold text-error/85"
            phx-click="reject_prompt"
            phx-value-id={record.id}
          >
            Reject
          </button>
        </div>
        <span
          :if={@confirming_reject_id == record.id}
          class="flex items-center gap-2 shrink-0"
          phx-window-keydown="reject_cancel"
          phx-key="escape"
        >
          <span class="text-xs text-base-content/60">reject at MITRE?</span>
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
        </span>
      </div>
    </.summary_panel>
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
    <.summary_panel
      :if={@count > 0}
      id="rejected-panel"
      label="Rejected"
      dot="bg-error/60"
      count={@count}
      open?={@open?}
      toggle="toggle_rejected"
      records_id="rejected-ids"
      class="mt-4"
    >
      <:fact :if={@id_range} label="span" value={@id_range} mono?={true} />
      <:fact :if={@latest} label="last" value={format_date(@latest.rejected_at)} />
      <div
        :for={record <- @records}
        class="grid grid-cols-[10rem_1fr] items-center gap-3 py-1 text-sm"
      >
        <span class="font-mono text-xs text-base-content/60">{record.cve_id}</span>
        <span class="text-xs text-base-content/50 tabular-nums">
          rejected {format_date(record.rejected_at)}
        </span>
      </div>
    </.summary_panel>
    """
  end
end
