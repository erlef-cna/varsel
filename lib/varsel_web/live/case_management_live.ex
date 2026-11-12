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

  The face lives in `?face=`, and `page`, `q` and the board's view ride along
  in the URL: `sort` orders the cases inside a row, `packages` orders the
  rows, `assignee` filters to one person's cases for those who assign cases.
  So both faces, any search and the view are deep-linkable and survive a face
  switch. The browser remembers the view, and a visit that names none of it
  gets it back.
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
  alias Varsel.Cases.RepoUrl
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
       gh_open?: false,
       assignable?: Cases.can_assign_case_user?(socket.assigns.current_user, %{})
     )}
  end

  @impl Phoenix.LiveView
  def handle_params(params, _uri, socket) do
    face = if params["face"] == "archive", do: :archive, else: :pipeline
    query = params["q"] || ""
    scope = params["scope"] || "all"
    fetched = {face, query, scope, params["page"]}
    socket = assign(socket, :view, parse_view(params))

    # A patch that only reorders or filters the board works on the cases
    # already fetched.
    socket =
      if socket.assigns[:fetched] == fetched do
        assign_board(socket.assigns.pipeline_cases, socket)
      else
        socket
        |> assign(face: face, query: query, scope: scope, fetched: fetched)
        |> assign_cve_record_matches()
        |> keep_pipeline_live()
        |> keep_archive_live(params)
      end

    {:noreply, socket}
  end

  defp parse_view(params) do
    %{
      cases: LaneSort.parse(params["sort"]),
      packages: PackageSort.parse(params["packages"]),
      assignee: parse_assignee(params["assignee"])
    }
  end

  # ------------------------------------------------------------- pipeline face

  # The pipeline is never paginated: one query for the active states, laid
  # out in memory. keep_live carries the PubSub reactivity (case:all) so the
  # board updates live.
  defp keep_pipeline_live(socket) do
    socket.endpoint.unsubscribe("case:all")

    keep_live(socket, :pipeline_cases, &list_pipeline_cases/2,
      subscribe: "case:all",
      results: :lose,
      after_fetch: &assign_board/2
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
  # refetches the board, so the arrival is checked from here.
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

  defp assign_board(cases, socket) do
    %{view: view, query: query, current_user: viewer, assignable?: assignable?} = socket.assigns

    # A search narrows `cases`, so the totals and the people the pipeline's
    # cases are assigned to then need the whole pipeline.
    pipeline = if query == "", do: cases, else: list_pipeline_overview(socket)
    totals = Enum.frequencies_by(pipeline, & &1.state)
    people = assignees(pipeline, viewer)

    {assignee, assignee_id} =
      if assignable?, do: resolve_assignee(view.assignee, people, viewer), else: {"all", nil}

    shown = cases |> assigned_to(assignee_id) |> LaneSort.sort(view.cases)
    shown_counts = Enum.frequencies_by(shown, & &1.state)
    narrowed? = query != "" or not is_nil(assignee_id)

    assignee_options = [
      {"all", "Everyone"},
      {"me", "Me"} | Enum.map(people, &{&1.id, &1.display_name})
    ]

    socket
    |> assign(
      columns: columns(totals, shown_counts, narrowed?),
      rows: package_rows(shown, view.packages),
      assignee: assignee,
      assignee_label: assignee != "all" && assignee_options |> List.keyfind(assignee, 0) |> elem(1),
      assignee_options: assignee_options,
      assignee_users: Map.new([{"me", viewer} | Enum.map(people, &{&1.id, &1})]),
      pipeline_count: totals |> Map.values() |> Enum.sum(),
      pipeline_match_count: length(shown)
    )
    |> check_gh_answer()
  end

  # A column counts what the search and the assignee filter leave while
  # either is active, and everything in its state otherwise. Publishing is a
  # handoff a case passes through in moments, so its column shows only while
  # something is in it.
  defp columns(totals, shown_counts, narrowed?) do
    for state <- @lane_states, state != :publishing or Map.has_key?(totals, state) do
      shown = Map.get(shown_counts, state, 0)

      %{
        key: state,
        id: "lane-#{state}",
        label: Phoenix.Naming.humanize(state),
        dot: lane_dot(state),
        count: if(narrowed?, do: shown, else: Map.get(totals, state, 0)),
        empty?: shown == 0
      }
    end
  end

  defp list_pipeline_overview(socket) do
    Cases.list_cases!(
      actor: socket.assigns.current_user,
      load: [assignments: [user: [:display_name, :avatar_url]]],
      query: Case |> Ash.Query.filter(state in ^@lane_states) |> Ash.Query.select([:state])
    )
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

  # The menu's choice and the user id it filters by. An id that no case in
  # the pipeline is assigned to filters nothing.
  defp resolve_assignee("me", _people, viewer), do: {"me", viewer.id}

  defp resolve_assignee(id, people, _viewer) do
    if Enum.any?(people, &(&1.id == id)), do: {id, id}, else: {"all", nil}
  end

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
         to when not is_nil(to) <- Enum.find(@lane_states, &(Atom.to_string(&1) == to)),
         {_can?, move} <- Map.get(@moves, {case_record.state, to}),
         {:error, error} <- move.(case_record, actor: socket.assigns.current_user) do
      {:noreply, put_flash(socket, :error, errors_to_string(error))}
    else
      _moved_or_no_such_move -> {:noreply, socket}
    end
  end

  def handle_event("search", %{"query" => query}, socket) do
    to =
      if socket.assigns.face == :archive do
        archive_path(socket.assigns.scope, query, nil, socket.assigns.view)
      else
        pipeline_path(query, socket.assigns.view)
      end

    {:noreply, push_patch(socket, to: to)}
  end

  def handle_event("sort", %{"selection" => selection}, socket) do
    patch_view(socket, %{cases: LaneSort.parse(selection)})
  end

  def handle_event("sort_packages", %{"selection" => selection}, socket) do
    patch_view(socket, %{packages: PackageSort.parse(selection)})
  end

  def handle_event("assignee", %{"selection" => selection}, socket) do
    patch_view(socket, %{assignee: parse_assignee(selection)})
  end

  # What the browser remembered, or nothing at all after a force-refresh,
  # which puts the defaults back.
  def handle_event("restore_view", params, socket) do
    patch_view(socket, parse_view(params))
  end

  def handle_event("scope", %{"scope" => scope}, socket) do
    {:noreply, push_patch(socket, to: archive_path(scope, socket.assigns.query, nil, socket.assigns.view))}
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

  defp patch_view(socket, changes) do
    view = Map.merge(socket.assigns.view, changes)

    {:noreply, push_patch(socket, to: pipeline_path(socket.assigns.query, view))}
  end

  defp pipeline_path(query, view) do
    case drop_empty([q: (query != "" && query) || nil] ++ view_params(view)) do
      [] -> ~p"/cases"
      params -> ~p"/cases?#{params}"
    end
  end

  # The board's view rides along even on the archive face, which does not use
  # it, so switching back to the pipeline returns to the board you left.
  defp archive_path(scope, query, page, view) do
    params =
      drop_empty(
        [face: "archive", scope: scope, page: page, q: (query != "" && query) || nil] ++
          view_params(view)
      )

    ~p"/cases?#{params}"
  end

  defp view_params(view) do
    [
      sort: LaneSort.param(view.cases),
      packages: PackageSort.param(view.packages),
      assignee: view.assignee
    ]
  end

  defp drop_empty(params), do: Enum.reject(params, fn {_key, value} -> is_nil(value) end)

  defp format_short_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%b %-d")

  defp stale?(seconds, state), do: seconds >= Map.fetch!(@stale_after, state)

  # "4 d" / "22 h" style age used on pipeline cards, distinct from
  # `CaseComponents.relative_timestamp/1`'s "4d ago" prose form.
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
  attr :view, :map, required: true
  attr :cve_record_match_count, :integer, required: true
  attr :pipeline_count, :integer, required: true
  attr :archive_count, :integer, required: true
  attr :pipeline_match_count, :integer, required: true
  attr :archive_match_count, :integer, required: true

  defp face_tabs(assigns) do
    ~H"""
    <div class="flex items-center gap-4 text-sm mt-1.5">
      <.link patch={pipeline_path(@query, @view)}>
        <.scope_tab
          active?={@face == :pipeline}
          label="Pipeline"
          count={face_count(@face == :pipeline, @query, @pipeline_count, @pipeline_match_count)}
          matched?={searched_elsewhere?(@face == :pipeline, @query)}
        />
      </.link>
      <.link patch={archive_path("all", @query, nil, @view)}>
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
      <.page_header wide_actions>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>Cases</:title>
        <:meta>
          <.face_tabs
            face={@face}
            query={@query}
            view={@view}
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
            id="board-memory"
            phx-hook="BoardMemory"
            data-sort={LaneSort.param(@view.cases)}
            data-packages={PackageSort.param(@view.packages)}
            data-assignee={@view.assignee}
            hidden
          ></span>
          <.console_menu
            :if={@face == :pipeline and @assignable?}
            id="assignee-filter"
            label="Assignee"
            icon="hero-user-mini"
            value={@assignee}
            options={@assignee_options}
            event="assignee"
            searchable
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
          <.console_menu
            :if={@face == :pipeline}
            id="board-sort"
            label="Sort"
            groups={[
              %{
                label: "Packages",
                event: "sort_packages",
                value: @view.packages,
                options: PackageSort.options()
              },
              %{label: "Cases", event: "sort", value: @view.cases, options: LaneSort.options()}
            ]}
          />
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
          columns={@columns}
          rows={@rows}
          empty?={@pipeline_count == 0}
          query={@query}
          assignee={@assignee_label}
          archive_match_count={@archive_match_count}
          can_open?={Cases.can_open_case?(@current_user, %{})}
          view={@view}
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
          view={@view}
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

  attr :columns, :list, required: true
  attr :rows, :list, required: true
  attr :empty?, :boolean, required: true, doc: "the pipeline holds no case at all"
  attr :query, :string, required: true
  attr :assignee, :any, required: true, doc: "who the board is filtered to, by name, or false"
  attr :archive_match_count, :integer, required: true
  attr :can_open?, :boolean, required: true
  attr :view, :map, required: true
  attr :cve_record_match_count, :integer, required: true

  defp pipeline_face(assigns) do
    assigns = assign(assigns, :zero_matches?, assigns.query != "" and assigns.rows == [])

    ~H"""
    <div :if={@zero_matches?} class="text-center text-sm text-base-content/70 py-8">
      No active cases match '{@query}' —
      <.count_label
        count={@archive_match_count}
        singular="match"
        plural="matches"
      /> in
      <.link patch={archive_path("all", @query, nil, @view)} class="link text-primary">
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
        <.package_link :for={{label, href} <- row.links} href={href} label={label} />
      </:row_head>
      <:cell :let={{row, column}}>
        <.pipeline_card
          :for={case_record <- Map.get(row.by_state, column.key, [])}
          case_record={case_record}
        />
      </:cell>
    </BoardComponents.matrix>

    <p
      :if={@assignee && @rows == [] && !@empty? && @query == ""}
      id="no-assigned-cases"
      class="text-center text-sm text-base-content/70 mt-4"
    >
      {if @assignee == "Me",
        do: "No case in the pipeline is assigned to you.",
        else: "No case in the pipeline is assigned to #{@assignee}."}
    </p>

    <p :if={@empty? and @query == ""} class="text-center text-sm text-base-content/70 mt-4">
      No active cases.
      <span :if={@can_open?}>
        <button
          type="button"
          class="link text-primary"
          phx-click="open_case_dialog"
          phx-value-choice="blank"
        >
          Open a case
        </button>
        to start one, or browse
      </span>
      <span :if={!@can_open?}>Browse</span>
      the <.link patch={archive_path("all", "", nil, @view)} class="link text-primary">archive</.link>.
    </p>
    """
  end

  # A case with several packages groups under its first.
  defp package_key(case_record), do: case_record |> package_chips() |> List.first()

  # Where the package a row stands for lives, as `{label, url}`: its page on
  # each registry it ships to, and its repository.
  defp package_links(cards) do
    packages = Enum.flat_map(cards, &Enum.take(&1.affected_packages, 1))

    registries =
      for package <- packages,
          channel <- package.channels,
          name = [channel.namespace, channel.name] |> Enum.reject(&is_nil/1) |> Enum.join("/"),
          link = VarselWeb.CveView.registry_page(channel.purl_type, name),
          uniq: true,
          do: link

    forge =
      Enum.find_value(packages, fn package ->
        package.repo_url &&
          {package.repo_url |> RepoUrl.parse() |> RepoUrl.forge_name(), package.repo_url}
      end)

    registries ++ List.wrap(forge)
  end

  # One row per package across every state. The cases without a package
  # lead, since that is where a fresh report waits.
  defp package_rows(cases, order) do
    {bare, packaged} =
      cases
      |> Enum.group_by(&package_key/1)
      |> Enum.map(fn {package, cards} ->
        %{
          package: package,
          label: package || "No package",
          links: if(package, do: package_links(cards), else: []),
          total: length(cards),
          opened_at: cards |> Enum.map(& &1.inserted_at) |> Enum.min(DateTime),
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

    bare ++ PackageSort.sort(packaged, order)
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
                if(@stale?, do: "text-[color:var(--warning-ink)]", else: "text-base-content/70")
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
  attr :view, :map, required: true

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
          view={@view}
        />
        <.scope_link
          scope={@scope}
          value="published"
          label="Published"
          count={@published_count}
          query={@query}
          view={@view}
        />
        <.scope_link
          scope={@scope}
          value="closed"
          label="Closed"
          count={@closed_count}
          query={@query}
          view={@view}
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
  attr :view, :map, required: true

  defp scope_link(assigns) do
    assigns = assign(assigns, :active?, assigns.scope == assigns.value)

    ~H"""
    <.link patch={archive_path(@value, @query, nil, @view)}>
      <.scope_tab active?={@active?} label={@label} count={@count} />
    </.link>
    """
  end
end
