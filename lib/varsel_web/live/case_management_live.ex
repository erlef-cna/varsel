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

  The face lives in `?face=` (`page`/`q`/`sort` ride along), so both faces,
  any search and the lane order are deep-linkable and survive a face switch.
  Lane-clip expansion is ephemeral UI state (not in the URL, reset on reload)
  per the checklist.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.AdvisoryComponents, only: [gh_command_modal: 1]
  import VarselWeb.CveView, only: [package_display_name: 1]
  import VarselWeb.LivePagination, only: [change_page: 3, jump_to_page: 3]
  import VarselWeb.UserComponents, only: [avatar_disc: 1]

  alias AshPhoenix.Form
  alias Varsel.Cases
  alias Varsel.Cases.AffectedPackage
  alias Varsel.Cases.Case
  alias Varsel.CVE
  alias Varsel.GitHub.Advisories
  alias Varsel.GitHub.Credentials
  alias VarselWeb.BoardComponents
  alias VarselWeb.CaseManagementLive.LaneSort

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
    {:ok,
     assign(socket,
       page_title: "Cases",
       expanded_lanes: MapSet.new(),
       open_case_open?: false,
       open_case_dialog: nil,
       advisory_reach: nil,
       open_case_form: nil,
       advisory_form: nil,
       gh: nil,
       gh_open?: false
     )}
  end

  @impl Phoenix.LiveView
  def handle_params(params, _uri, socket) do
    face = if params["face"] == "archive", do: :archive, else: :pipeline
    query = params["q"] || ""

    socket =
      socket
      |> assign(
        face: face,
        query: query,
        scope: params["scope"] || "all",
        sort: LaneSort.parse(params["sort"])
      )
      |> assign_cve_record_matches()
      |> keep_pipeline_live()
      |> keep_archive_live(params)

    {:noreply, socket}
  end

  # ------------------------------------------------------------- pipeline face

  # The pipeline is never paginated: one query for the active states, grouped
  # into lanes in memory. keep_live carries the PubSub reactivity (case:all)
  # so lane contents update live.
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
        assignments: [user: [:avatar_url, :display_name]],
        affected_packages: Ash.Query.select(AffectedPackage, [:product, :vendor, :position])
      ],
      query:
        Case
        |> Ash.Query.filter(state in ^@lane_states)
        |> filter_search(socket.assigns.query)
    )
  end

  # The answer to a gh open arrives out of band, on the POC's own terminal.
  # What reaches the page is the case's own create notification, which
  # refetches the lanes, so the arrival is checked from here.
  defp check_gh_answer(%{assigns: %{gh: %{request: %{id: id}}}} = socket) do
    case Cases.get_github_manual_request(id, actor: socket.assigns.current_user) do
      {:ok, %{completed_at: %DateTime{}, case_id: case_id}} when is_binary(case_id) ->
        socket
        |> assign(gh: nil, open_case_dialog: nil)
        |> push_navigate(to: ~p"/cases/#{case_id}/github")

      _pending ->
        socket
    end
  end

  defp check_gh_answer(socket), do: socket

  defp assign_lanes(cases, socket) do
    grouped = Enum.group_by(cases, & &1.state)
    totals = lane_totals(socket)
    searching? = socket.assigns.query != ""

    lanes =
      for state <- @lane_states do
        cards = grouped |> Map.get(state, []) |> LaneSort.sort(socket.assigns.sort)
        total = Map.get(totals, state, 0)

        %{
          state: state,
          label: Phoenix.Naming.humanize(state),
          dot: lane_dot(state),
          count: total,
          match_count: length(cards),
          # The header count reflects matches while a query is active; the
          # live total returns when the input clears.
          display_count: if(searching?, do: length(cards), else: total),
          cards: cards
        }
      end

    socket
    |> assign(:lanes, lanes)
    |> assign(:pipeline_count, totals |> Map.values() |> Enum.sum())
    |> assign(:pipeline_match_count, length(cases))
    |> check_gh_answer()
  end

  # The rows are already filtered by the search, so a lane's total needs its
  # own query.
  defp lane_totals(socket) do
    [
      actor: socket.assigns.current_user,
      query: Case |> Ash.Query.filter(state in ^@lane_states) |> Ash.Query.select([:state])
    ]
    |> Cases.list_cases!()
    |> Enum.frequencies_by(& &1.state)
  end

  # A CVE ID with no case finds nothing here, which reads as "it does not
  # exist". The count says where it does live. The read policy filters the
  # records to what this actor may see.
  defp assign_cve_record_matches(socket) do
    count =
      case String.trim(socket.assigns.query) do
        "" ->
          0

        term ->
          %{}
          |> CVE.query_to_list_all_cve_records(actor: socket.assigns.current_user)
          |> Ash.Query.filter(matches_query(query: ^String.downcase(term)))
          |> Ash.count!()
      end

    assign(socket, :cve_record_match_count, count)
  end

  # ------------------------------------------------------------- archive face
  defp lane_dot(:draft), do: "bg-warning"
  defp lane_dot(:review), do: "bg-info"
  defp lane_dot(:approved), do: "bg-[color:var(--violet)]"
  defp lane_dot(:publishing), do: "bg-info"

  defp filter_search(base, query) do
    case String.trim(query) do
      "" -> base
      term -> Ash.Query.filter(base, matches_query(query: ^String.downcase(term)))
    end
  end

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
      load: [
        :cve_id,
        :cvss_score,
        :severity_bucket,
        affected_packages:
          AffectedPackage
          |> Ash.Query.select([:product, :vendor, :position])
          |> Ash.Query.load(channels: [:purl])
      ],
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

  # `archive_count` stays unfiltered: an empty result reads differently when
  # the archive itself is empty.
  defp assign_archive_counts(_page, socket) do
    counts =
      Case
      |> Ash.Query.filter(state in ^@archive_states)
      |> filter_search(socket.assigns.query)
      |> Ash.Query.select([:state])
      |> Ash.read!(actor: socket.assigns.current_user)
      |> Enum.frequencies_by(& &1.state)

    published = Map.get(counts, :published, 0)
    closed = Map.get(counts, :closed, 0)

    archive_count =
      Case
      |> Ash.Query.filter(state in ^@archive_states)
      |> Ash.count!(actor: socket.assigns.current_user)

    socket
    |> assign(:archive_published_count, published)
    |> assign(:archive_closed_count, closed)
    |> assign(:archive_count, archive_count)
    |> assign(:archive_match_count, published + closed)
  end

  defp assign_dialog_form(socket, :blank) do
    form =
      Case
      |> Form.for_create(:open, as: "form", actor: socket.assigns.current_user)
      |> to_form()

    assign(socket, :open_case_form, form)
  end

  defp assign_dialog_form(socket, :advisory) do
    form =
      Case
      |> Form.for_create(:open_from_github_advisory,
        as: "form",
        actor: socket.assigns.current_user
      )
      |> to_form()

    # --------------------------------------------------------------- events

    assign(socket, :advisory_form, form)
  end

  # The POC runs the read themselves where no credential of ours reaches the
  # repository. The domain decides whether they may.
  defp gh_open?(reach, url, actor) do
    not submittable_reach?(reach) and
      Cases.can_prepare_manual_open?(actor, url, %{}, validate?: true)
  end

  # A global database entry belongs to no repository, so no credential of
  # ours reads it and there is nothing to warn about.
  defp advisory_reach(url, actor) do
    case Advisories.parse(url) do
      {:ok, %{owner: owner, repo: repo}} -> Credentials.reach(actor, owner, repo)
      {:ok, _global_entry} -> :global
      :error -> nil
    end
  end

  @impl Phoenix.LiveView
  def handle_event("open_case", %{"form" => params}, socket) do
    case Form.submit(socket.assigns.open_case_form, params: params) do
      {:ok, case_record} ->
        {:noreply, push_navigate(socket, to: ~p"/cases/#{case_record.id}")}

      {:error, form} ->
        {:noreply, assign(socket, :open_case_form, form)}
    end
  end

  def handle_event("open_case_from_advisory", %{"form" => params}, socket) do
    case Form.submit(socket.assigns.advisory_form, params: params) do
      {:ok, case_record} ->
        {:noreply, push_navigate(socket, to: ~p"/cases/#{case_record.id}/github")}

      {:error, form} ->
        {:noreply, assign(socket, :advisory_form, form)}
    end
  end

  def handle_event("search", %{"query" => query}, socket) do
    to =
      if socket.assigns.face == :archive do
        archive_path(socket.assigns.scope, query, nil, socket.assigns.sort)
      else
        pipeline_path(query, socket.assigns.sort)
      end

    {:noreply, push_patch(socket, to: to)}
  end

  def handle_event("sort", %{"selection" => selection}, socket) do
    sort = LaneSort.parse(selection)

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, sort))}
  end

  def handle_event("scope", %{"scope" => scope}, socket) do
    {:noreply, push_patch(socket, to: archive_path(scope, socket.assigns.query, nil, socket.assigns.sort))}
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

  def handle_event("open_case_dialog", %{"choice" => choice}, socket) do
    dialog = if choice == "advisory", do: :advisory, else: :blank

    {:noreply,
     socket
     |> assign(:open_case_open?, false)
     |> assign(:open_case_dialog, dialog)
     |> assign(:advisory_reach, nil)
     |> assign(:gh, nil)
     |> assign(:gh_open?, false)
     |> assign_dialog_form(dialog)}
  end

  def handle_event("close_open_case_dialog", _params, socket) do
    {:noreply,
     socket
     |> assign(:open_case_dialog, nil)
     |> assign(:advisory_reach, nil)
     |> assign(:gh, nil)
     |> assign(:gh_open?, false)}
  end

  def handle_event("close_gh", _params, socket), do: {:noreply, assign(socket, :gh, nil)}

  def handle_event("gh_open", _params, socket) do
    url = Form.value(socket.assigns.advisory_form, :advisory_url)

    case Cases.prepare_manual_open(url, actor: socket.assigns.current_user) do
      {:ok, request} ->
        {:noreply, assign(socket, :gh, %{request: request, token: request.__metadata__.token})}

      {:error, error} ->
        {:noreply, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  def handle_event("validate_open_case", %{"form" => params}, socket) do
    {:noreply, assign(socket, :open_case_form, Form.validate(socket.assigns.open_case_form, params))}
  end

  def handle_event("validate_advisory", %{"form" => params}, socket) do
    url = params["advisory_url"] || ""
    reach = advisory_reach(url, socket.assigns.current_user)

    {:noreply,
     socket
     |> assign(:advisory_form, Form.validate(socket.assigns.advisory_form, params))
     |> assign(:advisory_reach, reach)
     |> assign(:gh_open?, gh_open?(reach, url, socket.assigns.current_user))}
  end

  def handle_event("toggle_lane", %{"lane" => lane}, socket) do
    state = String.to_existing_atom(lane)

    # ------------------------------------------------------------------ helpers

    expanded =
      if MapSet.member?(socket.assigns.expanded_lanes, state) do
        MapSet.delete(socket.assigns.expanded_lanes, state)
      else
        MapSet.put(socket.assigns.expanded_lanes, state)
      end

    {:noreply, assign(socket, :expanded_lanes, expanded)}
  end

  defp pipeline_path(query, sort) do
    case drop_empty(q: (query != "" && query) || nil, sort: LaneSort.param(sort)) do
      [] -> ~p"/cases"
      params -> ~p"/cases?#{params}"
    end
  end

  # The sort rides along even on the archive face, which does not use it, so
  # switching back to the pipeline returns to the board you left.
  defp archive_path(scope, query, page, sort) do
    params =
      drop_empty(
        face: "archive",
        scope: scope,
        page: page,
        q: (query != "" && query) || nil,
        sort: LaneSort.param(sort)
      )

    ~p"/cases?#{params}"
  end

  defp drop_empty(params), do: Enum.reject(params, fn {_key, value} -> is_nil(value) end)

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
    Enum.map(case_record.affected_packages, &(&1.product || &1.vendor))
  end

  # One entry per distribution channel, as the CVE list names them: a package
  # published to Hex and GitHub reads as both.
  defp package_purls(case_record) do
    Enum.flat_map(case_record.affected_packages, &channel_purls/1)
  end

  # A channel with no purl is a service; it falls back to the package's name.
  defp channel_purls(package) do
    name = package.product || package.vendor

    case package.channels do
      [] -> [{nil, name}]
      channels -> Enum.map(channels, &{&1.purl, name})
    end
  end

  defp needs_owner?(case_record) do
    case_record.state in [:review, :approved] and case_record.assignments == []
  end

  attr :face, :atom, required: true
  attr :query, :string, required: true
  attr :sort, :atom, required: true
  attr :cve_record_match_count, :integer, required: true
  attr :pipeline_count, :integer, required: true
  attr :archive_count, :integer, required: true
  attr :pipeline_match_count, :integer, required: true
  attr :archive_match_count, :integer, required: true

  defp face_tabs(assigns) do
    ~H"""
    <div class="flex items-center gap-4 text-sm mt-1.5">
      <.link patch={pipeline_path(@query, @sort)}>
        <.scope_tab
          active?={@face == :pipeline}
          label="Pipeline"
          count={face_count(@face == :pipeline, @query, @pipeline_count, @pipeline_match_count)}
          matched?={searched_elsewhere?(@face == :pipeline, @query)}
        />
      </.link>
      <.link patch={archive_path("all", @query, nil, @sort)}>
        <.scope_tab
          active?={@face == :archive}
          label="Archive"
          count={face_count(@face == :archive, @query, @archive_count, @archive_match_count)}
          matched?={searched_elsewhere?(@face == :archive, @query)}
        />
      </.link>
      <span :if={@query != ""} class="text-xs text-base-content/50">
        matches for '{@query}'
      </span>
      <.link
        :if={@cve_record_match_count > 0}
        navigate={~p"/cves?#{[q: @query]}"}
        class="text-xs text-info hover:underline"
      >
        {@cve_record_match_count} in CVEs →
      </.link>
    </div>
    """
  end

  # The tint marks the face you are not looking at.
  defp searched_elsewhere?(active?, query), do: query != "" and not active?

  defp face_count(_active?, "", total, _matched), do: total
  defp face_count(_active?, _query, _total, matched), do: matched

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app
      flash={@flash}
      current_user={@current_user}
      current_path={@current_path}
      socket={@socket}
    >
      <.page_header>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>Cases</:title>
        <:meta>
          <.face_tabs
            face={@face}
            query={@query}
            sort={@sort}
            cve_record_match_count={@cve_record_match_count}
            pipeline_count={@pipeline_count}
            archive_count={@archive_count}
            pipeline_match_count={@pipeline_match_count}
            archive_match_count={@archive_match_count}
          />
        </:meta>
        <:actions>
          <.console_menu
            :if={@face == :pipeline}
            id="lane-sort"
            label="Sort"
            value={@sort}
            options={LaneSort.options()}
            event="sort"
          />
          <.console_search id="case-search" value={@query} placeholder="Search all cases…" />
          <div :if={Cases.can_open_case?(@current_user, %{})} class="relative">
            <button type="button" class="btn btn-sm btn-eef" phx-click="toggle_open_case">
              Open case
            </button>
            <ul
              :if={@open_case_open?}
              class="menu menu-sm absolute right-0 top-full mt-2 z-20 w-64 rounded-box border border-base-300 bg-base-200 p-1.5 shadow-lg"
              phx-click-away="close_open_case"
              phx-window-keydown="close_open_case"
              phx-key="escape"
            >
              <li>
                <button type="button" phx-click="open_case_dialog" phx-value-choice="blank">
                  <.icon name="hero-document-plus" class="size-4 shrink-0" />
                  <span class="flex flex-col items-start gap-0.5">
                    <span>Blank case</span>
                    <span class="text-xs text-base-content/60">Start from a working title</span>
                  </span>
                </button>
              </li>
              <li :if={Cases.can_open_case_from_github_advisory?(@current_user, %{})}>
                <button type="button" phx-click="open_case_dialog" phx-value-choice="advisory">
                  <.icon name="hero-shield-exclamation" class="size-4 shrink-0" />
                  <span class="flex flex-col items-start gap-0.5">
                    <span>From a GitHub advisory</span>
                    <span class="text-xs text-base-content/60">Fill it in from GHSA content</span>
                  </span>
                </button>
              </li>
            </ul>
          </div>
        </:actions>
      </.page_header>

      <.page_container width={:wide}>
        <.pipeline_face
          :if={@face == :pipeline}
          lanes={@lanes}
          query={@query}
          expanded_lanes={@expanded_lanes}
          archive_match_count={@archive_match_count}
          can_open?={Cases.can_open_case?(@current_user, %{})}
          sort={@sort}
          cve_record_match_count={@cve_record_match_count}
        />
        <.archive_face
          :if={@face == :archive}
          cases={@archive_cases}
          scope={@scope}
          query={@query}
          published_count={@archive_published_count}
          closed_count={@archive_closed_count}
          archive_count={@archive_count}
          archive_match_count={@archive_match_count}
          sort={@sort}
        />
      </.page_container>

      <.modal
        :if={@open_case_dialog == :blank}
        id="open-case-blank"
        title="Open a blank case"
        on_cancel="close_open_case_dialog"
      >
        <.form
          for={@open_case_form}
          id="open-case-form"
          phx-submit="open_case"
          phx-change="validate_open_case"
          class="space-y-4"
        >
          <div>
            <.input
              field={@open_case_form[:title]}
              type="text"
              placeholder="What the case is about"
              required
              phx-mounted={JS.focus()}
            >
              <:label>Working title</:label>
            </.input>
            <p class="mt-1.5 text-xs text-base-content/60">
              A draft opens with you assigned. You can rename it later.
            </p>
          </div>
          <div class="modal-action">
            <button type="button" phx-click="close_open_case_dialog" class="btn btn-sm btn-ghost">
              Cancel
            </button>
            <button type="submit" class="btn btn-sm btn-eef">Open case</button>
          </div>
        </.form>
      </.modal>

      <.modal
        :if={@open_case_dialog == :advisory}
        id="open-case-advisory-modal"
        title="Open a case from a GitHub advisory"
        on_cancel="close_open_case_dialog"
      >
        <.form
          for={@advisory_form}
          id="open-case-advisory-form"
          phx-submit="open_case_from_advisory"
          phx-change="validate_advisory"
          class="space-y-4"
        >
          <div>
            <.input
              field={@advisory_form[:advisory_url]}
              type="text"
              placeholder="https://github.com/owner/repo/security/advisories/GHSA-…"
              required
              autocomplete="off"
              class="input input-bordered w-full font-mono text-sm"
              phx-mounted={JS.focus()}
            >
              <:label>Advisory</:label>
            </.input>
            <p class="mt-1.5 text-xs text-base-content/60">
              The case takes its title, description, CVSS v4, CWEs, credits and affected
              packages from the advisory. A GHSA id on its own reads the global database
              entry.
            </p>
          </div>
          <.advisory_reach_notice reach={@advisory_reach} gh={@gh_open?} />
          <div class="modal-action">
            <button type="button" phx-click="close_open_case_dialog" class="btn btn-sm btn-ghost">
              Cancel
            </button>
            <button :if={@gh_open?} type="button" phx-click="gh_open" class="btn btn-sm btn-eef">
              Do it with gh
            </button>
            <button
              :if={not @gh_open?}
              type="submit"
              class="btn btn-sm btn-eef"
              disabled={not submittable_reach?(@advisory_reach)}
            >
              Open case
            </button>
          </div>
        </.form>
      </.modal>

      <.gh_command_modal
        :if={@gh}
        request={@gh.request}
        token={@gh.token}
        base_url={VarselWeb.Endpoint.url()}
      />
    </Layouts.app>
    """
  end

  # Every other reach is a reason that makes `Credentials.run/5` answer
  # `{:no_credential, _}`, which `GitHubAdvisory.Fetch` turns into the same
  # message the notice shows. nil is an input that names no repository yet.
  defp submittable_reach?(reach), do: reach in [nil, :user, :installation, :global]

  # Reach comes from the synced installation rows, so this says nothing about
  # whether GitHub will answer the read itself.
  attr :reach, :atom, required: true
  attr :gh, :boolean, required: true

  defp advisory_reach_notice(%{reach: reach} = assigns) do
    if submittable_reach?(reach), do: ~H"", else: refused_reach(assigns)
  end

  defp refused_reach(assigns) do
    ~H"""
    <div class="alert alert-info text-sm">
      <.icon name="hero-information-circle" class="size-5 shrink-0" />
      <span>
        This {Credentials.message(@reach)}.
        <span :if={@gh}>
          Do it with gh instead: you get a command to run in your own terminal,
          as your GitHub account.
        </span>
      </span>
    </div>
    """
  end

  attr :lanes, :list, required: true
  attr :query, :string, required: true
  attr :expanded_lanes, :any, required: true
  attr :archive_match_count, :integer, required: true
  attr :can_open?, :boolean, required: true
  attr :sort, :atom, required: true
  attr :cve_record_match_count, :integer, required: true

  defp pipeline_face(assigns) do
    all_empty? = Enum.all?(assigns.lanes, &(&1.count == 0))
    zero_matches? = assigns.query != "" and Enum.all?(assigns.lanes, &(&1.match_count == 0))
    assigns = assign(assigns, all_empty?: all_empty?, zero_matches?: zero_matches?)

    ~H"""
    <div :if={@zero_matches?} class="text-center text-sm text-base-content/70 py-8">
      No active cases match '{@query}' —
      <.count_label
        count={@archive_match_count}
        singular="match"
        plural="matches"
      /> in
      <.link patch={archive_path("all", @query, nil, @sort)} class="link text-primary">
        Archive →
      </.link>
      <span :if={@cve_record_match_count > 0}>
        ,
        <.count_label
          count={@cve_record_match_count}
          singular="match"
          plural="matches"
        /> in
        <.link navigate={~p"/cves?#{[q: @query]}"} class="link text-primary">
          CVEs →
        </.link>
      </span>
    </div>

    <BoardComponents.board :if={!@zero_matches?}>
      <.lane
        :for={lane <- @lanes}
        lane={lane}
        expanded?={MapSet.member?(@expanded_lanes, lane.state)}
      />
    </BoardComponents.board>

    <p
      :if={@all_empty? and @query == "" and @can_open?}
      class="text-center text-sm text-base-content/60 mt-4"
    >
      No active cases.
      <button
        type="button"
        class="link text-primary"
        phx-click="open_case_dialog"
        phx-value-choice="blank"
      >
        Open a case
      </button>
      to start one, or browse the <.link
        patch={archive_path("all", "", nil, @sort)}
        class="link text-primary"
      >archive</.link>.
    </p>

    <p
      :if={@all_empty? and @query == "" and !@can_open?}
      class="text-center text-sm text-base-content/60 mt-4"
    >
      No active cases. Browse the <.link
        patch={archive_path("all", "", nil, @sort)}
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
    <BoardComponents.lane
      id={"lane-#{@lane.state}"}
      label={@lane.label}
      dot={@lane.dot}
      count={@lane.display_count}
      cards?={@visible_cards != []}
      quiet?={@collapsed?}
    >
      <.pipeline_card
        :for={case_record <- @visible_cards}
        case_record={case_record}
        lane_state={@lane.state}
      />

      <:footer :if={@overflowing?}>
        <button
          type="button"
          phx-click="toggle_lane"
          phx-value-lane={@lane.state}
          class="w-full py-2 cursor-pointer"
        >
          <%= if @expanded? do %>
            Show fewer ▴
          <% else %>
            Show all {length(@lane.cards)} ▾
          <% end %>
        </button>
      </:footer>
    </BoardComponents.lane>
    """
  end

  attr :case_record, :any, required: true
  attr :lane_state, :atom, required: true

  defp pipeline_card(assigns) do
    ~H"""
    <.link navigate={~p"/cases/#{@case_record.id}"}>
      <BoardComponents.card>
        <:title>{@case_record.title || "Untitled"}</:title>

        <:chips>
          <.severity_chip score={@case_record.cvss_score} />
          <BoardComponents.card_chip :for={product <- package_chips(@case_record)}>
            {product}
          </BoardComponents.card_chip>
        </:chips>

        <:footer>
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
                <BoardComponents.unclaimed_disc />
              <% true -> %>
            <% end %>
          </span>
        </:footer>
      </BoardComponents.card>
    </.link>
    """
  end

  attr :cases, :any, required: true
  attr :scope, :string, required: true
  attr :query, :string, required: true
  attr :published_count, :integer, required: true
  attr :closed_count, :integer, required: true
  attr :archive_count, :integer, required: true
  attr :archive_match_count, :integer, required: true
  attr :sort, :atom, required: true

  defp archive_face(assigns) do
    ~H"""
    <.list_card empty?={@cases.results == []}>
      <:tabs>
        <.scope_link
          scope={@scope}
          value="all"
          label="All"
          count={@archive_match_count}
          query={@query}
          sort={@sort}
        />
        <.scope_link
          scope={@scope}
          value="published"
          label="Published"
          count={@published_count}
          query={@query}
          sort={@sort}
        />
        <.scope_link
          scope={@scope}
          value="closed"
          label="Closed"
          count={@closed_count}
          query={@query}
          sort={@sort}
        />
      </:tabs>
      <:empty>
        {if @archive_count == 0,
          do: "Nothing archived yet — cases land here when they are published or closed.",
          else: "No archived cases match."}
      </:empty>

      <div class="overflow-x-auto hidden md:block">
        <table class="table w-full">
          <thead>
            <tr class="text-[0.65rem] font-bold uppercase tracking-wider text-base-content/50">
              <th class="w-32">CVE ID</th>
              <th>Title</th>
              <th class="w-56">Packages</th>
              <th class="w-20">Severity</th>
              <th class="w-44">State</th>
              <th class="w-32">Published</th>
            </tr>
          </thead>
          <tbody>
            <tr
              :for={case_record <- @cases.results}
              class="hover:bg-base-300/40 group cursor-pointer"
              phx-click={JS.navigate(~p"/cases/#{case_record.id}")}
            >
              <td class="font-mono text-xs whitespace-nowrap text-base-content/60">
                {if case_record.state == :closed, do: "—", else: case_record.cve_id || "—"}
              </td>
              <td class={[
                "max-w-md truncate",
                if(case_record.state == :closed,
                  do: "text-base-content/50",
                  else: "font-semibold group-hover:text-primary"
                )
              ]}>
                {case_record.title || "Untitled"}
              </td>
              <td phx-click={%JS{}}>
                <div
                  :for={{purl, fallback} <- package_purls(case_record)}
                  class="text-xs break-all"
                >
                  <.package_display_name purl={purl} fallback={fallback} link={true} />
                </div>
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
              <td class="font-mono text-xs whitespace-nowrap text-base-content/60">
                {if case_record.state == :closed, do: "—", else: format_date(case_record.published_at)}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="md:hidden">
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
                <span
                  :for={product <- package_chips(case_record)}
                  class="text-xs text-base-content/60"
                >
                  {product}
                </span>
                <span class="font-mono text-xs text-base-content/60">{format_date(
                  case_record.published_at
                )}</span>
              <% end %>
            </div>
          </.link>
        </div>
      </div>

      <:footer id="archive-pager">
        <.pagination page={@cases} />
      </:footer>
    </.list_card>
    """
  end

  attr :case_record, :any, required: true

  defp archive_state_cell(assigns) do
    ~H"""
    <span
      :if={@case_record.state == :published}
      class="whitespace-nowrap text-base-content/60 text-sm"
    >
      ● Published
    </span>
    <span :if={@case_record.state == :closed} class="whitespace-nowrap text-base-content/50 text-sm">
      ● Closed · {format_short_date(@case_record.updated_at)}
    </span>
    """
  end

  attr :scope, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true
  attr :query, :string, required: true
  attr :sort, :atom, required: true

  defp scope_link(assigns) do
    assigns = assign(assigns, :active?, assigns.scope == assigns.value)

    ~H"""
    <.link patch={archive_path(@value, @query, nil, @sort)}>
      <.scope_tab active?={@active?} label={@label} count={@count} />
    </.link>
    """
  end
end
