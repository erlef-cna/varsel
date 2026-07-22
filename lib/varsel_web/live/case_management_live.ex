# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive do
  @moduledoc """
  The /cases console — two faces sharing one band.

  **Pipeline** (default) is a never-paginated kanban of the four active
  states (draft/review/approved/publishing), policy-scoped same as before:
  POCs see every case, supporters see only their assignments. **Archive** is
  a paginated, searchable table scoped to published + closed, collated by
  archived-at (published_at, or `updated_at` for closed rows — see
  `archive_query/2`) descending.

  The face lives in `?face=` (`page`/`q` ride along), so both faces and any
  search are deep-linkable and survive a face switch. Lane-clip expansion is
  ephemeral UI state (not in the URL, reset on reload) per the checklist.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CaseComponents, only: [avatar_disc: 1]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]

  alias Varsel.Cases
  alias Varsel.Cases.Case

  require Ash.Query
  require Ash.Sort

  @lane_states [:draft, :review, :approved, :publishing]
  @archive_states [:published, :closed]
  @lane_clip 8

  # Per-lane staleness thresholds, in seconds.
  @stale_after %{
    draft: 14 * 86_400,
    review: 5 * 86_400,
    approved: 3 * 86_400,
    publishing: 86_400
  }

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    {:ok, assign(socket, page_title: "Cases", expanded_lanes: MapSet.new(), open_case_open?: false)}
  end

  @impl Phoenix.LiveView
  def handle_params(params, _uri, socket) do
    face = if params["face"] == "archive", do: :archive, else: :pipeline
    query = params["q"] || ""

    socket =
      socket
      |> assign(face: face, query: query, scope: params["scope"] || "all")
      |> keep_pipeline_live()
      |> keep_archive_live(params)

    {:noreply, socket}
  end

  # ------------------------------------------------------------- pipeline face

  # The pipeline is never paginated: one query for the whole active-state
  # working set, grouped into lanes in memory. keep_live still carries the
  # PubSub reactivity (case:all) so lane contents update live.
  defp keep_pipeline_live(socket) do
    socket.endpoint.unsubscribe("case:all")

    keep_live(socket, :pipeline_cases, &list_pipeline_cases/2,
      subscribe: "case:all",
      results: :lose,
      after_fetch: &assign_lanes/2
    )
  end

  defp list_pipeline_cases(socket, _page_opts) do
    Cases.list_cases!(
      actor: socket.assigns.current_user,
      load: [
        :cve_id,
        :cvss_score,
        :severity_bucket,
        assignments: [:user],
        affected_packages: Ash.Query.select(Varsel.Cases.AffectedPackage, [:product, :vendor, :position])
      ],
      query: Ash.Query.filter(Case, state in ^@lane_states)
    )
  end

  defp assign_lanes(cases, socket) do
    matches? = search_predicate(socket.assigns.query)
    grouped = Enum.group_by(cases, & &1.state)

    searching? = socket.assigns.query != ""

    lanes =
      for state <- @lane_states do
        cards = grouped |> Map.get(state, []) |> Enum.sort_by(& &1.updated_at, {:asc, DateTime})
        matched = Enum.filter(cards, matches?)

        %{
          state: state,
          label: Phoenix.Naming.humanize(state),
          dot: lane_dot(state),
          count: length(cards),
          match_count: length(matched),
          # The header count reflects matches while a query is active; the
          # live total returns when the input clears.
          display_count: if(searching?, do: length(matched), else: length(cards)),
          cards: matched
        }
      end

    socket
    |> assign(:lanes, lanes)
    |> assign(:pipeline_count, length(cases))
    |> assign(:pipeline_match_count, cases |> Enum.filter(matches?) |> length())
  end

  defp lane_dot(:draft), do: "bg-warning"
  defp lane_dot(:review), do: "bg-info"
  defp lane_dot(:approved), do: "bg-[color:var(--violet)]"
  defp lane_dot(:publishing), do: "bg-info"

  defp search_predicate("") do
    fn _case_record -> true end
  end

  defp search_predicate(query) do
    term = String.downcase(query)

    # is_binary/1, not truthiness: an unloaded calculation is an
    # %Ash.NotLoaded{} struct, which is truthy.
    fn case_record ->
      (is_binary(case_record.title) &&
         String.contains?(String.downcase(case_record.title), term)) ||
        (is_binary(case_record.cve_id) &&
           String.contains?(String.downcase(case_record.cve_id), term))
    end
  end

  # ------------------------------------------------------------- archive face

  defp keep_archive_live(socket, params) do
    socket.endpoint.unsubscribe("case:all")

    initial_page_opts =
      case params["page"] do
        nil ->
          [count: true, offset: 0, limit: 25]

        page ->
          offset = ((page |> String.to_integer() |> max(1)) - 1) * 25
          [count: true, offset: offset, limit: 25]
      end

    socket
    |> assign(:archive_page_opts, initial_page_opts)
    |> keep_live(:archive_cases, &list_archive_cases/2,
      subscribe: "case:all",
      results: :lose,
      after_fetch: &assign_archive_counts/2
    )
  end

  # keep_live passes `nil` on the very first fetch (the mount/handle_params
  # path above stashes the page derived from `?page=` in the assign for that
  # case) and the previously-stored page opts on every subsequent refetch —
  # PubSub-triggered reloads and LivePagination's change_page/jump_to_page.
  defp list_archive_cases(socket, page_opts) do
    Cases.list_cases!(
      actor: socket.assigns.current_user,
      load: [:cve_id, :cvss_score, :severity_bucket],
      query: archive_query(socket.assigns.scope, socket.assigns.query),
      page: page_opts || socket.assigns.archive_page_opts
    )
  end

  # Sorted by archived-at descending: published_at for published rows,
  # updated_at for closed rows. `Case` has no `closed_at` column (see the
  # implementation report) — `updated_at` is exact for a terminal state
  # transition, since `close` is the last write a closed case ever receives.
  defp archive_query(scope, query) do
    Case
    |> Ash.Query.filter(state in ^@archive_states)
    |> filter_archive_scope(scope)
    |> filter_search(query)
    |> Ash.Query.sort([
      {Ash.Sort.expr_sort(if(is_nil(published_at), do: updated_at, else: published_at)), :desc}
    ])
  end

  defp filter_archive_scope(base, "published"), do: Ash.Query.filter(base, state == :published)
  defp filter_archive_scope(base, "closed"), do: Ash.Query.filter(base, state == :closed)
  defp filter_archive_scope(base, _all), do: base

  defp filter_search(base, query) do
    case query |> String.trim() |> String.downcase() do
      "" ->
        base

      term ->
        Ash.Query.filter(
          base,
          contains(string_downcase(title), ^term) or
            contains(string_downcase(cve_record.cve_id), ^term)
        )
    end
  end

  defp assign_archive_counts(_page, socket) do
    counts =
      [
        actor: socket.assigns.current_user,
        query: Case |> Ash.Query.filter(state in ^@archive_states) |> Ash.Query.select([:state])
      ]
      |> Cases.list_cases!()
      |> Enum.frequencies_by(& &1.state)

    published = Map.get(counts, :published, 0)
    closed = Map.get(counts, :closed, 0)

    archive_match_count =
      if socket.assigns.query == "" do
        published + closed
      else
        # Counted with the same server-side filter the archive face uses —
        # the in-memory predicate would need :cve_id loaded on every row.
        [
          actor: socket.assigns.current_user,
          query:
            "all"
            |> archive_query(socket.assigns.query)
            |> Ash.Query.select([:id])
        ]
        |> Cases.list_cases!()
        |> length()
      end

    socket
    |> assign(:archive_published_count, published)
    |> assign(:archive_closed_count, closed)
    |> assign(:archive_count, published + closed)
    |> assign(:archive_match_count, archive_match_count)
  end

  # --------------------------------------------------------------- events

  @impl Phoenix.LiveView
  def handle_event("open_case", %{"title" => title}, socket) do
    socket =
      case Cases.open_case(%{title: title}, actor: socket.assigns.current_user) do
        {:ok, case_record} ->
          push_navigate(socket, to: ~p"/cases/#{case_record.id}")

        {:error, error} ->
          put_flash(socket, :error, "Could not open case: #{errors_to_string(error)}")
      end

    {:noreply, socket}
  end

  def handle_event("search", %{"query" => query}, socket) do
    to =
      if socket.assigns.face == :archive do
        archive_path(socket, socket.assigns.scope, query, nil)
      else
        pipeline_path(query)
      end

    {:noreply, push_patch(socket, to: to)}
  end

  def handle_event("scope", %{"scope" => scope}, socket) do
    {:noreply, push_patch(socket, to: archive_path(socket, scope, socket.assigns.query, nil))}
  end

  def handle_event("paginate", %{"page" => target}, socket) do
    {:noreply, change_page(socket, :archive_cases, target)}
  end

  def handle_event("jump_page", %{"page" => target}, socket) do
    {:noreply, jump_to_page(socket, :archive_cases, target)}
  end

  def handle_event("toggle_open_case", _params, socket) do
    {:noreply, assign(socket, :open_case_open?, not socket.assigns.open_case_open?)}
  end

  def handle_event("close_open_case", _params, socket) do
    {:noreply, assign(socket, :open_case_open?, false)}
  end

  def handle_event("toggle_lane", %{"lane" => lane}, socket) do
    state = String.to_existing_atom(lane)

    expanded =
      if MapSet.member?(socket.assigns.expanded_lanes, state) do
        MapSet.delete(socket.assigns.expanded_lanes, state)
      else
        MapSet.put(socket.assigns.expanded_lanes, state)
      end

    {:noreply, assign(socket, :expanded_lanes, expanded)}
  end

  defp pipeline_path(""), do: ~p"/cases"
  defp pipeline_path(query), do: ~p"/cases?#{[q: query]}"

  defp archive_path(_socket, scope, query, page) do
    params =
      Enum.reject(
        [face: "archive", scope: scope, page: page, q: (query != "" && query) || nil],
        fn {_k, v} ->
          is_nil(v)
        end
      )

    ~p"/cases?#{params}"
  end

  # ------------------------------------------------------------------ helpers

  defp poc?(%{role: :poc}), do: true
  defp poc?(_user), do: false

  defp count_label(1, singular, _plural), do: "1 #{singular}"
  defp count_label(count, _singular, plural), do: "#{count} #{plural}"

  defp format_dt(nil), do: "—"
  defp format_dt(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")

  defp format_short_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%b %-d")

  # "4 d" / "22 h" style age used on pipeline cards, distinct from
  # `CaseComponents.relative_timestamp/1`'s "4d ago" prose form. Crossing the
  # lane's staleness threshold switches to "<age> in <lane>" (amber, via the
  # caller's `stale?` class).
  defp lane_age(%DateTime{} = at, state) do
    seconds = DateTime.diff(DateTime.utc_now(), at, :second)

    if stale?(seconds, state) do
      "#{format_age(seconds)} in #{state |> Phoenix.Naming.humanize() |> String.downcase()}"
    else
      format_age(seconds)
    end
  end

  defp stale?(seconds, state), do: seconds >= Map.fetch!(@stale_after, state)

  defp format_age(seconds) when seconds < 3600, do: "#{max(div(seconds, 60), 1)} m"
  defp format_age(seconds) when seconds < 86_400, do: "#{div(seconds, 3600)} h"
  defp format_age(seconds), do: "#{div(seconds, 86_400)} d"

  defp package_chips(case_record) do
    case_record
    |> Map.get(:affected_packages, [])
    |> case do
      %Ash.NotLoaded{} -> []
      packages -> Enum.map(packages, &(&1.product || &1.vendor))
    end
  end

  defp needs_owner?(case_record) do
    case_record.state in [:review, :approved] and case_record.assignments == []
  end

  defp errors_to_string(error) do
    error
    |> Ash.Error.to_error_class()
    |> Map.get(:errors, [])
    |> Enum.map_join("\n", &Exception.message/1)
  end

  attr :socket, :any, required: true
  attr :face, :atom, required: true
  attr :query, :string, required: true
  attr :pipeline_count, :integer, required: true
  attr :archive_count, :integer, required: true
  attr :pipeline_match_count, :integer, required: true
  attr :archive_match_count, :integer, required: true

  defp face_tabs(assigns) do
    ~H"""
    <div class="flex items-center gap-4 text-sm mt-1.5">
      <.link
        patch={pipeline_path(@query)}
        class={[
          "pb-1",
          if(@face == :pipeline,
            do: "font-bold text-base-content shadow-[inset_0_-2px_0_var(--eef-blue)]",
            else: "text-base-content/60"
          )
        ]}
      >
        Pipeline
        <span class={[
          "font-bold tabular-nums",
          cond do
            @query != "" and @face != :pipeline -> "text-info"
            @face == :pipeline -> "text-primary"
            true -> "text-base-content/50"
          end
        ]}>
          {if @query != "" and @face != :pipeline, do: @pipeline_match_count, else: @pipeline_count}
        </span>
      </.link>
      <.link
        patch={archive_path(@socket, "all", @query, nil)}
        class={[
          "pb-1",
          if(@face == :archive,
            do: "font-bold text-base-content shadow-[inset_0_-2px_0_var(--eef-blue)]",
            else: "text-base-content/60"
          )
        ]}
      >
        Archive
        <span class={[
          "font-bold tabular-nums",
          cond do
            @query != "" and @face != :archive -> "text-info"
            @face == :archive -> "text-primary"
            true -> "text-base-content/50"
          end
        ]}>
          {if @query != "" and @face != :archive, do: @archive_match_count, else: @archive_count}
        </span>
      </.link>
      <span :if={@query != ""} class="text-xs text-base-content/50">
        matches for '{@query}'
      </span>
    </div>
    """
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.flash_group flash={@flash} />

    <div class="console-band">
      <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6 flex flex-wrap items-end justify-between gap-x-8 gap-y-4">
        <div>
          <p class="eef-eyebrow mb-1">CNA Console</p>
          <h1 class="text-2xl font-bold leading-tight">Cases</h1>
          <.face_tabs
            socket={@socket}
            face={@face}
            query={@query}
            pipeline_count={@pipeline_count}
            archive_count={@archive_count}
            pipeline_match_count={@pipeline_match_count}
            archive_match_count={@archive_match_count}
          />
        </div>
        <div class="flex flex-wrap items-center gap-2 pb-0.5">
          <form id="case-search" phx-change="search" phx-submit="search">
            <.console_search value={@query} placeholder="Search all cases…" />
          </form>
          <div :if={poc?(@current_user)} class="relative">
            <button type="button" class="btn btn-sm btn-eef" phx-click="toggle_open_case">
              Open case
            </button>
            <div
              :if={@open_case_open?}
              class="absolute right-0 top-full mt-2 z-20 rounded-box border border-base-300 bg-base-200 p-3 shadow-lg"
              phx-click-away="close_open_case"
              phx-window-keydown="close_open_case"
              phx-key="escape"
            >
              <form phx-submit="open_case" class="flex items-center gap-2">
                <input
                  id="open-case-title"
                  type="text"
                  name="title"
                  placeholder="Working title"
                  required
                  class="input input-bordered input-sm w-56"
                  phx-mounted={JS.focus()}
                />
                <button type="submit" class="btn btn-sm btn-eef">Open</button>
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-6xl py-6">
      <.pipeline_face
        :if={@face == :pipeline}
        lanes={@lanes}
        query={@query}
        expanded_lanes={@expanded_lanes}
        archive_match_count={@archive_match_count}
        socket={@socket}
      />
      <.archive_face
        :if={@face == :archive}
        cases={@archive_cases}
        scope={@scope}
        query={@query}
        published_count={@archive_published_count}
        closed_count={@archive_closed_count}
        archive_count={@archive_count}
        socket={@socket}
      />
    </div>
    """
  end

  attr :lanes, :list, required: true
  attr :query, :string, required: true
  attr :expanded_lanes, :any, required: true
  attr :archive_match_count, :integer, required: true
  attr :socket, :any, required: true

  defp pipeline_face(assigns) do
    all_empty? = Enum.all?(assigns.lanes, &(&1.count == 0))
    zero_matches? = assigns.query != "" and Enum.all?(assigns.lanes, &(&1.match_count == 0))
    assigns = assign(assigns, all_empty?: all_empty?, zero_matches?: zero_matches?)

    ~H"""
    <div :if={@zero_matches?} class="text-center text-sm text-base-content/70 py-8">
      No active cases match '{@query}' — {count_label(@archive_match_count, "match", "matches")} in
      <.link patch={archive_path(@socket, "all", @query, nil)} class="link text-primary">
        Archive →
      </.link>
    </div>

    <div :if={!@zero_matches?} class="grid grid-cols-1 md:grid-cols-4 gap-3 items-start">
      <.lane
        :for={lane <- @lanes}
        lane={lane}
        expanded?={MapSet.member?(@expanded_lanes, lane.state)}
      />
    </div>

    <p :if={@all_empty? and @query == ""} class="text-center text-sm text-base-content/60 mt-4">
      No active cases.
      <button type="button" class="link text-primary" phx-click="toggle_open_case">
        Open a case
      </button>
      to start one, or browse the <.link
        patch={archive_path(@socket, "all", "", nil)}
        class="link text-primary"
      >archive</.link>.
    </p>
    """
  end

  attr :lane, :map, required: true
  attr :expanded?, :boolean, required: true

  defp lane(assigns) do
    clipped? = not assigns.expanded? and length(assigns.lane.cards) > @lane_clip

    visible_cards =
      if clipped?, do: Enum.take(assigns.lane.cards, @lane_clip), else: assigns.lane.cards

    assigns =
      assign(assigns,
        visible_cards: visible_cards,
        collapsed?: assigns.lane.count == 0,
        overflowing?: length(assigns.lane.cards) > @lane_clip
      )

    ~H"""
    <div id={"lane-#{@lane.state}"} class="rounded-box border border-base-300 bg-base-200">
      <div class={[
        "flex items-center gap-2 px-3.5 py-2.5 text-[0.7rem] font-bold uppercase tracking-wider text-base-content/60",
        if(@collapsed?,
          do: "max-md:border-b-0 border-b border-base-300",
          else: "border-b border-base-300"
        )
      ]}>
        <span class={["size-1.5 rounded-full shrink-0", @lane.dot]}></span>
        {@lane.label}
        <span class="ml-auto text-base-content/50 tabular-nums font-bold">
          {@lane.display_count}
        </span>
      </div>

      <div :if={@visible_cards != []} class="flex flex-col gap-2.5 p-2.5 min-h-12">
        <.pipeline_card
          :for={case_record <- @visible_cards}
          case_record={case_record}
          lane_state={@lane.state}
        />
      </div>
      <div
        :if={@visible_cards == []}
        class={[@collapsed? && "max-md:hidden", "text-center text-sm text-base-content/40 py-3"]}
      >
        —
      </div>

      <button
        :if={@overflowing?}
        type="button"
        phx-click="toggle_lane"
        phx-value-lane={@lane.state}
        class="w-full text-center border-t border-base-300 py-2 text-[0.74rem] font-semibold text-primary cursor-pointer"
      >
        <%= if @expanded? do %>
          Show fewer ▴
        <% else %>
          Show all {length(@lane.cards)} ▾
        <% end %>
      </button>
    </div>
    """
  end

  attr :case_record, :any, required: true
  attr :lane_state, :atom, required: true

  defp pipeline_card(assigns) do
    ~H"""
    <.link
      navigate={~p"/cases/#{@case_record.id}"}
      class="lane-card block rounded-lg border border-base-300 p-2.5 hover:border-[color:var(--eef-blue)] cursor-pointer"
    >
      <div class="text-[0.8rem] font-semibold leading-snug">{@case_record.title || "Untitled"}</div>

      <div class="flex flex-wrap gap-1.5 mt-2">
        <.severity_chip score={@case_record.cvss_score} />
        <span
          :for={product <- package_chips(@case_record)}
          class="font-mono text-[0.71rem] text-base-content/60 bg-base-200 border border-base-300 rounded px-1.5 py-0.5 whitespace-nowrap"
        >
          {product}
        </span>
      </div>

      <div class="flex items-center justify-between gap-2 mt-2.5">
        <span class="font-mono text-[0.68rem] text-base-content/50">
          {@case_record.cve_id || "no CVE yet"}
        </span>
        <span class="flex items-center gap-1.5">
          <span class={[
            "text-[0.68rem] whitespace-nowrap",
            if(
              stale?(
                DateTime.diff(DateTime.utc_now(), @case_record.updated_at, :second),
                @lane_state
              ),
              do: "text-warning",
              else: "text-base-content/50"
            )
          ]}>
            {lane_age(@case_record.updated_at, @lane_state)}
          </span>
          <%= cond do %>
            <% @case_record.assignments != [] -> %>
              <span class="flex items-center -space-x-1">
                <.avatar_disc
                  :for={
                    {assignment, index} <- Enum.with_index(Enum.take(@case_record.assignments, 2))
                  }
                  user={assignment.user}
                  variant={if rem(index, 2) == 0, do: :a, else: :b}
                />
                <span
                  :if={length(@case_record.assignments) > 2}
                  class="text-[0.62rem] text-base-content/50 pl-1"
                >
                  +{length(@case_record.assignments) - 2}
                </span>
              </span>
            <% needs_owner?(@case_record) -> %>
              <span
                class="inline-flex size-[21px] shrink-0 items-center justify-center rounded-full border-[1.5px] border-dashed border-base-content/40 text-base-content/40 text-xs"
                title="Needs an owner"
              >
                –
              </span>
            <% true -> %>
          <% end %>
        </span>
      </div>
    </.link>
    """
  end

  attr :cases, :any, required: true
  attr :scope, :string, required: true
  attr :query, :string, required: true
  attr :published_count, :integer, required: true
  attr :closed_count, :integer, required: true
  attr :archive_count, :integer, required: true
  attr :socket, :any, required: true

  defp archive_face(assigns) do
    ~H"""
    <div class="rounded-box border border-base-300 bg-base-200 overflow-hidden">
      <div class="flex items-center gap-3.5 px-3.5 py-2 border-b border-base-300 text-[0.76rem] text-base-content/60">
        <.scope_link
          scope={@scope}
          value="all"
          label="All"
          count={@archive_count}
          query={@query}
          socket={@socket}
        />
        <.scope_link
          scope={@scope}
          value="published"
          label="Published"
          count={@published_count}
          query={@query}
          socket={@socket}
        />
        <.scope_link
          scope={@scope}
          value="closed"
          label="Closed"
          count={@closed_count}
          query={@query}
          socket={@socket}
        />
      </div>

      <div
        :if={@cases.results == [] and @archive_count == 0}
        class="text-center text-sm text-base-content/60 py-10"
      >
        Nothing archived yet — cases land here when they are published or closed.
      </div>

      <div
        :if={@cases.results == [] and @archive_count > 0}
        class="text-center text-sm text-base-content/60 py-10"
      >
        No archived cases match.
      </div>

      <div :if={@cases.results != []} class="overflow-x-auto hidden md:block">
        <table class="table w-full">
          <thead>
            <tr class="text-[0.65rem] font-bold uppercase tracking-wider text-base-content/50">
              <th>Title</th>
              <th>CVE ID</th>
              <th>Severity</th>
              <th>State</th>
              <th>Published</th>
            </tr>
          </thead>
          <tbody>
            <tr
              :for={case_record <- @cases.results}
              class="hover:bg-base-300/40 group cursor-pointer"
              phx-click={JS.navigate(~p"/cases/#{case_record.id}")}
            >
              <td class={[
                "max-w-md truncate",
                if(case_record.state == :closed,
                  do: "text-base-content/50",
                  else: "font-semibold group-hover:text-primary"
                )
              ]}>
                {case_record.title || "Untitled"}
              </td>
              <td class="font-mono text-xs text-base-content/60">
                {if case_record.state == :closed, do: "—", else: case_record.cve_id || "—"}
              </td>
              <td>
                <.severity_chip
                  :if={case_record.state != :closed and case_record.cvss_score}
                  score={case_record.cvss_score}
                />
              </td>
              <td>
                <.archive_state_cell case_record={case_record} />
              </td>
              <td class="font-mono text-xs text-base-content/60">
                {if case_record.state == :closed, do: "—", else: format_dt(case_record.published_at)}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div :if={@cases.results != []} class="md:hidden">
        <div
          :for={case_record <- @cases.results}
          class="border-b border-base-300 last:border-0 px-3.5 py-2.5"
        >
          <.link navigate={~p"/cases/#{case_record.id}"} class="block">
            <div class={[
              "text-[0.8rem] font-semibold leading-snug",
              case_record.state == :closed && "text-base-content/50 font-normal"
            ]}>
              {case_record.title || "Untitled"}
            </div>
            <div class="flex items-center gap-2 flex-wrap mt-1">
              <%= if case_record.state == :closed do %>
                <span class="text-[0.72rem] text-base-content/50">
                  ● Closed · {format_short_date(case_record.updated_at)}
                </span>
              <% else %>
                <.severity_chip :if={case_record.cvss_score} score={case_record.cvss_score} />
                <span class="font-mono text-xs text-base-content/60">{case_record.cve_id || "—"}</span>
                <span class="font-mono text-xs text-base-content/60">{format_dt(
                  case_record.published_at
                )}</span>
              <% end %>
            </div>
          </.link>
        </div>
      </div>

      <div :if={@cases.results != []} id="archive-pager-wide" class="hidden md:block">
        <.jump_pagination page={@cases} />
      </div>
      <div
        :if={@cases.results != [] and is_integer(@cases.count) and @cases.count > @cases.limit}
        id="archive-pager-narrow"
        class="md:hidden"
      >
        <div class="flex items-center justify-between gap-2 px-3.5 py-2 border-t border-base-300 text-xs text-base-content/60">
          <span>25 / page</span>
          <.pagination page={@cases} />
        </div>
      </div>
    </div>
    """
  end

  attr :case_record, :any, required: true

  defp archive_state_cell(assigns) do
    ~H"""
    <span :if={@case_record.state == :published} class="text-base-content/60 text-sm">
      ● Published
    </span>
    <span :if={@case_record.state == :closed} class="text-base-content/50 text-sm">
      ● Closed · {format_short_date(@case_record.updated_at)}
    </span>
    """
  end

  attr :scope, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true
  attr :query, :string, required: true
  attr :socket, :any, required: true

  defp scope_link(assigns) do
    ~H"""
    <.link
      patch={archive_path(@socket, @value, @query, nil)}
      class={if @scope == @value, do: "font-bold text-base-content", else: ""}
    >
      {@label}
      <span class={[
        "font-semibold tabular-nums ml-1",
        if(@scope == @value, do: "text-primary", else: "text-base-content/50")
      ]}>
        {@count}
      </span>
    </.link>
    """
  end
end
