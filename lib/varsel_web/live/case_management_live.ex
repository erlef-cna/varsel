# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseManagementLive do
  @moduledoc """
  The /cases console — two faces sharing one band.

  **Pipeline** (default) is a never-paginated matrix of the active cases: a
  column per state, submitted through publishing, and a row per affected
  package, so the cases for one package line up across the workflow. It is
  policy-scoped: POCs see every case, everyone else only their assignments,
  which for a reporter is the case their report opened. **Archive** is a paginated, searchable table
  scoped to published, closed and merged, collated by archived-at
  (published_at, or `updated_at` for the others — see `archive_query/2`)
  descending.

  The face lives in `?face=` (`page`/`q`/`sort`/`packages`/`assignee` ride along), so
  both faces, any search and the two sorts (the cases inside a row, and the
  package rows) and the assignee filter are deep-linkable and survive a face
  switch. The browser
  remembers the sorts and the assignee, and a visit that names none of them
  gets them back.
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
  alias VarselWeb.CaseManagementLive.PackageSort

  require Ash.Query
  require Ash.Sort

  @lane_states [:submitted, :triage, :draft, :review, :approved, :publishing]
  @archive_states [:published, :closed, :merged]

  # Per-lane staleness thresholds, in seconds. The security policy page
  # promises acknowledgment, and then assessment, within two business days.
  @stale_after %{
    submitted: 2 * 86_400,
    triage: 2 * 86_400,
    draft: 14 * 86_400,
    review: 5 * 86_400,
    approved: 3 * 86_400,
    publishing: 86_400
  }

  # The moves a drag between two pipeline columns stands for: the action's
  # authorization question and the action. Publishing is left out: it hands
  # the record to MITRE, which is not a thing to do by dropping a card.
  @moves %{
    {:submitted, :triage} => {&Cases.can_triage_case?/3, &Cases.triage_case/2},
    {:submitted, :draft} => {&Cases.can_accept_case?/3, &Cases.accept_case/2},
    {:triage, :draft} => {&Cases.can_accept_case?/3, &Cases.accept_case/2},
    {:draft, :review} => {&Cases.can_request_case_review?/3, &Cases.request_case_review/2},
    {:review, :draft} => {&Cases.can_request_case_changes?/3, &Cases.request_case_changes/2},
    {:review, :approved} => {&Cases.can_approve_case?/3, &Cases.approve_case/2},
    {:approved, :draft} => {&Cases.can_reopen_case?/3, &Cases.reopen_case/2}
  }

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Cases",
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
        sort: %{
          cases: LaneSort.parse(params["sort"]),
          packages: PackageSort.parse(params["packages"]),
          assignee: parse_assignee(params["assignee"])
        }
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
        affected_packages:
          AffectedPackage
          |> Ash.Query.select([:product, :vendor, :position, :repo_url])
          |> Ash.Query.load(channels: [:purl])
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
    {totals, assignees} = pipeline_overview(socket)

    assignee_id =
      assignee_id(socket.assigns.sort.assignee, assignees, socket.assigns.current_user)

    cases = assigned_to(cases, assignee_id)
    grouped = Enum.group_by(cases, & &1.state)
    searching? = socket.assigns.query != "" or not is_nil(assignee_id)

    lanes =
      for state <- @lane_states do
        cards = grouped |> Map.get(state, []) |> LaneSort.sort(socket.assigns.sort.cases)
        total = Map.get(totals, state, 0)

        %{
          state: state,
          key: state,
          id: "lane-#{state}",
          label: Phoenix.Naming.humanize(state),
          dot: lane_dot(state),
          count: total,
          match_count: length(cards),
          # The header count reflects matches while a query is active; the
          # live total returns when the input clears.
          display_count: if(searching?, do: length(cards), else: total),
          cards: cards,
          empty?: cards == []
        }
      end

    socket
    |> assign(:lanes, lanes)
    |> assign(:assignee_options, [
      {"all", "Everyone"},
      {"me", "Me"} | Enum.map(assignees, &{&1.id, &1.display_name})
    ])
    |> assign(
      :assignee_users,
      Map.new([{"me", socket.assigns.current_user} | Enum.map(assignees, &{&1.id, &1})])
    )
    |> assign(:assignee, assignee_value(socket.assigns.sort.assignee, assignee_id))
    |> assign(:pipeline_count, totals |> Map.values() |> Enum.sum())
    |> assign(:pipeline_match_count, length(cases))
    |> check_gh_answer()
  end

  # The rows are already filtered by the search, so the lanes' totals and the
  # people the pipeline's cases are assigned to need their own query.
  defp pipeline_overview(socket) do
    cases =
      Cases.list_cases!(
        actor: socket.assigns.current_user,
        load: [assignments: [user: [:display_name, :avatar_url]]],
        query: Case |> Ash.Query.filter(state in ^@lane_states) |> Ash.Query.select([:state])
      )

    {Enum.frequencies_by(cases, & &1.state), assignees(cases, socket.assigns.current_user)}
  end

  # Everyone but the viewer, who leads the menu as "Me" whether or not a case
  # is theirs.
  defp assignees(cases, viewer) do
    cases
    |> Enum.flat_map(& &1.assignments)
    |> Enum.map(& &1.user)
    |> Enum.reject(&(is_nil(&1) or &1.id == viewer.id))
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(&String.downcase(&1.display_name))
  end

  defp parse_assignee("me"), do: "me"

  defp parse_assignee(param) when is_binary(param) do
    case Ecto.UUID.cast(param) do
      {:ok, id} -> id
      :error -> nil
    end
  end

  defp parse_assignee(_param), do: nil

  # An id that no case in the pipeline is assigned to filters nothing.
  defp assignee_id(nil, _assignees, _viewer), do: nil
  defp assignee_id("me", _assignees, viewer), do: viewer.id
  defp assignee_id(id, assignees, _viewer), do: if(Enum.any?(assignees, &(&1.id == id)), do: id)

  defp assignee_value("me", _assignee_id), do: "me"
  defp assignee_value(_assignee, nil), do: "all"
  defp assignee_value(_assignee, assignee_id), do: assignee_id

  defp assigned_to(cases, nil), do: cases

  defp assigned_to(cases, user_id) do
    Enum.filter(cases, fn case_record ->
      Enum.any?(case_record.assignments, &(&1.user_id == user_id))
    end)
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
  defp lane_dot(:submitted), do: "bg-warning"
  defp lane_dot(:triage), do: "bg-info"
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

  defp filter_archive_scope(base, "closed"), do: Ash.Query.filter(base, state in [:closed, :merged])

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
    closed = Map.get(counts, :closed, 0) + Map.get(counts, :merged, 0)

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

  def handle_event("move_targets", %{"id" => id}, socket) do
    targets =
      case Enum.find(socket.assigns.pipeline_cases, &(&1.id == id)) do
        nil -> []
        case_record -> move_targets(case_record, socket.assigns.current_user)
      end

    {:reply, %{targets: targets}, socket}
  end

  def handle_event("move_case", %{"id" => id, "to" => to}, socket) do
    with %Case{} = case_record <- Enum.find(socket.assigns.pipeline_cases, &(&1.id == id)),
         {_can?, move} <- Enum.find_value(@moves, &move_to(&1, case_record.state, to)),
         {:error, error} <- move.(case_record, actor: socket.assigns.current_user) do
      {:noreply, put_flash(socket, :error, errors_to_string(error))}
    else
      _moved_or_no_such_move -> {:noreply, socket}
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
    sort = %{socket.assigns.sort | cases: LaneSort.parse(selection)}

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, sort))}
  end

  def handle_event("sort_packages", %{"selection" => selection}, socket) do
    sort = %{socket.assigns.sort | packages: PackageSort.parse(selection)}

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, sort))}
  end

  def handle_event("restore_sort", params, socket) do
    sort = %{
      socket.assigns.sort
      | cases: LaneSort.parse(params["sort"]),
        packages: PackageSort.parse(params["packages"]),
        assignee: parse_assignee(params["assignee"])
    }

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, sort))}
  end

  def handle_event("reset_sort", _params, socket) do
    sort = %{cases: LaneSort.default(), packages: PackageSort.default(), assignee: nil}

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, sort))}
  end

  def handle_event("assignee", %{"selection" => selection}, socket) do
    sort = %{socket.assigns.sort | assignee: parse_assignee(selection)}

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

  defp move_targets(case_record, actor) do
    for {{from, to}, {can?, _move}} <- @moves,
        from == case_record.state,
        can?.(actor, case_record, validate?: true),
        do: to
  end

  defp move_to({{from, to}, move}, from, to_param) do
    if Atom.to_string(to) == to_param, do: move
  end

  defp move_to(_move, _from, _to_param), do: nil

  defp pipeline_path(query, sort) do
    case drop_empty([q: (query != "" && query) || nil] ++ sort_params(sort)) do
      [] -> ~p"/cases"
      params -> ~p"/cases?#{params}"
    end
  end

  # The sort rides along even on the archive face, which does not use it, so
  # switching back to the pipeline returns to the board you left.
  defp archive_path(scope, query, page, sort) do
    params =
      drop_empty(
        [face: "archive", scope: scope, page: page, q: (query != "" && query) || nil] ++
          sort_params(sort)
      )

    ~p"/cases?#{params}"
  end

  defp sort_params(sort) do
    [
      sort: LaneSort.param(sort.cases),
      packages: PackageSort.param(sort.packages),
      assignee: sort.assignee
    ]
  end

  defp drop_empty(params), do: Enum.reject(params, fn {_key, value} -> is_nil(value) end)

  defp format_short_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%b %-d")

  # "4 d" / "22 h" style age used on pipeline cards, distinct from
  # `CaseComponents.relative_timestamp/1`'s "4d ago" prose form.
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
  attr :sort, :map, required: true
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

  attr :sort, :map, required: true

  # One control for both orders: the package rows, then the cases in a row.
  defp sort_menu(assigns) do
    assigns =
      assign(assigns,
        groups: [
          %{
            label: "Packages",
            event: "sort_packages",
            value: assigns.sort.packages,
            options: PackageSort.options()
          },
          %{label: "Cases", event: "sort", value: assigns.sort.cases, options: LaneSort.options()}
        ]
      )

    ~H"""
    <div id="board-sort" class="dropdown dropdown-end">
      <div
        tabindex="0"
        role="button"
        aria-label="Sort"
        class="btn btn-sm btn-ghost border border-base-300 font-normal gap-1.5"
      >
        <.icon name="hero-bars-arrow-down-mini" class="size-4 text-base-content/50 shrink-0" />
        <span class="text-base-content/70">Sort:</span>
        <span :for={{group, index} <- Enum.with_index(@groups)} class="flex items-center gap-1.5">
          <span :if={index > 0} class="text-base-content/70" aria-hidden="true">/</span>
          {Enum.find_value(group.options, fn {value, label} -> value == group.value && label end)}
        </span>
      </div>
      <ul
        tabindex="0"
        class="dropdown-content menu bg-base-100 text-base-content rounded-box shadow-lg border border-base-300 mt-2 w-52 p-2 z-50"
      >
        <%= for group <- @groups do %>
          <li class="menu-title text-[0.65rem] uppercase tracking-wider">{group.label}</li>
          <li :for={{value, label} <- group.options}>
            <button
              type="button"
              phx-click={group.event}
              phx-value-selection={value}
              aria-pressed={to_string(value == group.value)}
              class={[value == group.value && "menu-choice-active"]}
            >
              {label}
              <.icon :if={value == group.value} name="hero-check-mini" class="ml-auto size-4" />
            </button>
          </li>
        <% end %>
      </ul>
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
      <.page_header wide_actions>
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
          <span
            :if={@face == :pipeline}
            id="sort-memory"
            phx-hook="SortMemory"
            data-sort={LaneSort.param(@sort.cases)}
            data-packages={PackageSort.param(@sort.packages)}
            data-assignee={@sort.assignee}
            hidden
          ></span>
          <.console_menu
            :if={@face == :pipeline}
            id="assignee-filter"
            label="Assignee"
            icon="hero-user-mini"
            value={@assignee}
            options={@assignee_options}
            event="assignee"
          >
            <:lead :let={value}>
              <.avatar_disc :if={@assignee_users[value]} user={@assignee_users[value]} />
              <span
                :if={value == "all"}
                class="inline-flex size-[21px] shrink-0 items-center justify-center text-base-content/60"
              >
                <.icon name="hero-users-mini" class="size-4" />
              </span>
            </:lead>
          </.console_menu>
          <.sort_menu :if={@face == :pipeline} sort={@sort} />
          <.console_search id="case-search" value={@query} placeholder="Search all cases…" />
        </:actions>
        <:primary :if={Cases.can_open_case?(@current_user, %{})}>
          <div class="relative">
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
        </:primary>
      </.page_header>

      <.page_container width={:wide}>
        <.pipeline_face
          :if={@face == :pipeline}
          lanes={@lanes}
          query={@query}
          assignee={
            @assignee != "all" &&
              Enum.find_value(@assignee_options, fn {value, label} -> value == @assignee && label end)
          }
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
  attr :assignee, :any, required: true, doc: "who the board is filtered to, by name, or false"
  attr :archive_match_count, :integer, required: true
  attr :can_open?, :boolean, required: true
  attr :sort, :map, required: true
  attr :cve_record_match_count, :integer, required: true

  defp pipeline_face(assigns) do
    all_empty? = Enum.all?(assigns.lanes, &(&1.count == 0))
    zero_matches? = assigns.query != "" and Enum.all?(assigns.lanes, &(&1.match_count == 0))

    assigns =
      assign(assigns,
        all_empty?: all_empty?,
        zero_matches?: zero_matches?,
        columns: columns(assigns.lanes),
        rows: package_rows(assigns.lanes, assigns.sort)
      )

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

    <BoardComponents.matrix
      :if={!@zero_matches?}
      id="pipeline-board"
      head="Package"
      columns={@columns}
      rows={@rows}
      targets_event="move_targets"
      move_event="move_case"
    >
      <:row_head :let={row}>
        <div class="flex items-baseline gap-1.5 text-[0.78rem]">
          <span
            class={[
              "truncate font-semibold",
              if(row.package, do: "font-mono", else: "text-base-content/70")
            ]}
            title={row.label}
          >
            {row.label}
          </span>
          <span class="shrink-0 tabular-nums text-base-content/70">({row.total})</span>
        </div>
        <.package_link :if={row.links.hex} href={row.links.hex} label="hex.pm" />
        <.package_link
          :if={row.links.forge}
          href={elem(row.links.forge, 1)}
          label={elem(row.links.forge, 0)}
        />
      </:row_head>
      <:cell :let={{row, lane}}>
        <.pipeline_card
          :for={case_record <- Map.get(row.by_state, lane.state, [])}
          case_record={case_record}
        />
      </:cell>
    </BoardComponents.matrix>

    <p
      :if={@assignee && @rows == [] && !@all_empty? && @query == ""}
      id="no-assigned-cases"
      class="text-center text-sm text-base-content/70 mt-4"
    >
      {if @assignee == "Me",
        do: "No case in the pipeline is assigned to you.",
        else: "No case in the pipeline is assigned to #{@assignee}."}
    </p>

    <p
      :if={@all_empty? and @query == "" and @can_open?}
      class="text-center text-sm text-base-content/70 mt-4"
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
      class="text-center text-sm text-base-content/70 mt-4"
    >
      No active cases. Browse the <.link
        patch={archive_path("all", "", nil, @sort)}
        class="link text-primary"
      >archive</.link>.
    </p>
    """
  end

  # Publishing is a handoff a case passes through in moments, so its column
  # shows only while something is in it.
  defp columns(lanes) do
    lanes
    |> Enum.reject(&(&1.state == :publishing and &1.count == 0))
    |> Enum.map(&Map.put(&1, :count, &1.display_count))
  end

  # A case with several packages groups under its first.
  defp package_key(case_record), do: case_record |> package_chips() |> List.first()

  # Where the package a row stands for lives: its hex.pm page when it ships
  # there, and its repository.
  defp package_links(cards) do
    packages = Enum.flat_map(cards, &Enum.take(&1.affected_packages, 1))

    hex =
      packages
      |> Enum.flat_map(& &1.channels)
      |> Enum.find_value(fn channel ->
        if is_binary(channel.purl) and String.starts_with?(channel.purl, "pkg:hex/") do
          {_label, url} = VarselWeb.CveView.package_link(%{"packageURL" => channel.purl})
          url
        end
      end)

    %{hex: hex, forge: Enum.find_value(packages, &forge_link(&1.repo_url))}
  end

  defp forge_link(repo_url) when is_binary(repo_url) do
    case URI.parse(repo_url) do
      %URI{scheme: scheme, host: host} when scheme in ["http", "https"] and is_binary(host) ->
        {forge_name(host), repo_url}

      _other ->
        nil
    end
  end

  defp forge_link(_repo_url), do: nil

  defp forge_name("github.com"), do: "GitHub"
  defp forge_name("gitlab.com"), do: "GitLab"
  defp forge_name("codeberg.org"), do: "Codeberg"
  defp forge_name(host), do: host

  # One row per package across every lane. The cases without a package lead,
  # since that is where a fresh report waits.
  defp package_rows(lanes, sort) do
    {bare, packaged} =
      lanes
      |> Enum.flat_map(& &1.cards)
      |> Enum.group_by(&package_key/1)
      |> Enum.map(fn {package, cards} ->
        opened_at = cards |> Enum.map(& &1.inserted_at) |> Enum.min(DateTime)

        %{
          package: package,
          label: package || "No package",
          links: if(package, do: package_links(cards), else: %{hex: nil, forge: nil}),
          total: length(cards),
          opened_at: opened_at,
          max_score:
            cards
            |> Enum.map(& &1.cvss_score)
            |> Enum.reject(&is_nil/1)
            |> Enum.max(fn -> nil end),
          updated_at: cards |> Enum.map(& &1.updated_at) |> Enum.max(DateTime),
          by_state: Enum.group_by(cards, & &1.state)
        }
      end)
      |> Enum.split_with(&is_nil(&1.package))

    bare ++ PackageSort.sort(packaged, sort.packages)
  end

  attr :href, :string, required: true
  attr :label, :string, required: true

  defp package_link(assigns) do
    ~H"""
    <.link
      href={@href}
      target="_blank"
      rel="noopener"
      class="mt-1 flex w-fit items-center gap-1 text-[0.68rem] text-base-content/70 hover:text-primary hover:underline"
    >
      {@label}
      <.icon name="hero-arrow-top-right-on-square-mini" class="size-3" />
    </.link>
    """
  end

  attr :case_record, :any, required: true

  defp pipeline_card(assigns) do
    seconds = DateTime.diff(DateTime.utc_now(), assigns.case_record.updated_at, :second)

    assigns =
      assign(assigns,
        age: format_age(seconds),
        stale?: stale?(seconds, assigns.case_record.state)
      )

    ~H"""
    <.link
      navigate={~p"/cases/#{@case_record.id}"}
      title={@case_record.title}
      draggable="true"
      data-card={@case_record.id}
      class="block rounded-lg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[color:var(--eef-blue)]"
    >
      <BoardComponents.card>
        <:title>{@case_record.title || "Untitled"}</:title>
        <:meta>
          <.severity_chip score={@case_record.cvss_score} />
          <span
            :if={@case_record.cve_id}
            class="min-w-0 truncate font-mono text-[0.68rem] text-base-content/70"
          >
            {@case_record.cve_id}
          </span>
          <span class="ml-auto flex items-center gap-1.5">
            <span
              class={[
                "text-[0.68rem] tabular-nums whitespace-nowrap",
                if(@stale?, do: "text-[color:var(--stale-text)]", else: "text-base-content/70")
              ]}
              title={@stale? && "Waiting past this stage's threshold"}
              data-stale={@stale?}
            >
              {@age}
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
                    class="text-[0.62rem] text-base-content/70 pl-1"
                  >
                    +{length(@case_record.assignments) - 2}
                  </span>
                </span>
              <% needs_owner?(@case_record) -> %>
                <BoardComponents.unclaimed_disc />
              <% true -> %>
            <% end %>
          </span>
        </:meta>
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
  attr :sort, :map, required: true

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
                {if case_record.state != :published, do: "—", else: case_record.cve_id || "—"}
              </td>
              <td class={[
                "max-w-md truncate",
                if(case_record.state != :published,
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
                  :if={case_record.state == :published and case_record.cvss_score}
                  score={case_record.cvss_score}
                />
              </td>
              <td>
                <.archive_state_cell case_record={case_record} />
              </td>
              <td class="font-mono text-xs whitespace-nowrap text-base-content/60">
                {if case_record.state != :published,
                  do: "—",
                  else: format_date(case_record.published_at)}
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
              case_record.state != :published && "text-base-content/50 font-normal"
            ]}>
              {case_record.title || "Untitled"}
            </div>
            <div class="flex items-center gap-2 flex-wrap mt-1">
              <%= if case_record.state != :published do %>
                <span class="text-[0.72rem] text-base-content/50">
                  ● {Phoenix.Naming.humanize(case_record.state)} · {format_short_date(
                    case_record.updated_at
                  )}
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
    <span
      :if={@case_record.state != :published}
      class="whitespace-nowrap text-base-content/50 text-sm"
    >
      ● {Phoenix.Naming.humanize(@case_record.state)} · {format_short_date(@case_record.updated_at)}
    </span>
    """
  end

  attr :scope, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true
  attr :query, :string, required: true
  attr :sort, :map, required: true

  defp scope_link(assigns) do
    assigns = assign(assigns, :active?, assigns.scope == assigns.value)

    ~H"""
    <.link patch={archive_path(@value, @query, nil, @sort)}>
      <.scope_tab active?={@active?} label={@label} count={@count} />
    </.link>
    """
  end
end
