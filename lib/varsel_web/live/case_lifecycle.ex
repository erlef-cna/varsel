# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.CaseLifecycle do
  @moduledoc """
  What every case tab shares: the live case record, the tab list, and the
  lifecycle actions in the header.

  A tab calls `mount/3` once. That keeps the case record fresh from pub_sub,
  marks the case notifications read, and handles the lifecycle and comment
  reaction events its components push. The header only links to publishing:
  the act stays on the Publication tab, next to the validation it depends on.
  """
  use VarselWeb, :html

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import Phoenix.LiveView, only: [attach_hook: 4, connected?: 1, push_navigate: 2, put_flash: 3]
  import VarselWeb.CaseComponents, only: [case_actions: 1, case_picker: 1]

  alias Phoenix.LiveView.Socket
  alias Varsel.Cases
  alias Varsel.Cases.Case
  alias Varsel.Cases.CommentReaction.Emoji
  alias Varsel.CVE
  alias Varsel.Notifications

  require Ash.Query

  @topics ~w(case case_proposal case_comment)

  # The case's own state, which every tab renders in the header and the
  # lifecycle buttons. A tab adds the kinds its body shows.
  @lifecycle_kinds [
    :report_submitted,
    :review_requested,
    :unassigned_review_requested,
    :case_published,
    :case_assigned
  ]

  @form_modals %{"split" => :split, "reject" => :reject, "close" => :close}

  @merge_picker_limit 10

  @doc """
  Mounts the case on the socket as the `:case_record` assign and attaches
  the lifecycle event handlers.

  `load` names what to load on the case. `after_fetch` receives the loaded
  case and the socket after every fetch and returns the socket. A case the
  actor cannot read sends them back to the case list.

  `marks_read` names the notification kinds this tab's body shows, which it
  marks read on top of the case's own lifecycle kinds. A kind no open tab
  shows stays unread, so the bell keeps pointing at the tab that answers it.
  """
  @spec mount(Socket.t(), String.t(), load: list(), after_fetch: fun(), marks_read: [atom()]) ::
          Socket.t()
  def mount(socket, case_id, opts) do
    load = [
      :report_count,
      :comment_count,
      :unseen_comment_count,
      :upstream_cve,
      :upstream_cve_reserved | Keyword.fetch!(opts, :load)
    ]

    after_fetch = Keyword.fetch!(opts, :after_fetch)
    marks_read = @lifecycle_kinds ++ Keyword.get(opts, :marks_read, [])

    socket
    |> assign(case_id: case_id, lifecycle_modal: nil)
    |> attach_hook(__MODULE__, :handle_event, &handle_event/3)
    |> keep_live(:case_record, &load_case(&1, load),
      subscribe:
        Enum.map(@topics, &"#{&1}:#{case_id}") ++
          notification_topics(socket.assigns.current_user),
      after_fetch: &fetched(&1, &2, after_fetch, marks_read)
    )
  end

  # `:unseen_comment_count` reads notification rows. A background job writes
  # them after the comment's own broadcast, so the comment topic alone can
  # refetch before they exist.
  defp notification_topics(%{id: user_id}), do: ["notification:#{user_id}"]
  defp notification_topics(nil), do: []

  @doc """
  The tabs of a case, in display order. The Reports tab shows only when
  reports led to the case. A count of zero renders as no count at all.
  """
  def tabs(%{id: case_id} = case_record) do
    %{report_count: report_count, comment_count: comment_count} = case_record

    comment_count = if comment_count > 0, do: comment_count
    unseen_comments = unseen_label(case_record.unseen_comment_count)

    Enum.filter(
      [
        %{id: :workspace, label: "Workspace", navigate: ~p"/cases/#{case_id}"},
        %{
          id: :comments,
          label: "Comments",
          count: comment_count,
          unseen: unseen_comments,
          navigate: ~p"/cases/#{case_id}/comments"
        },
        report_count > 0 &&
          %{
            id: :reports,
            label: "Reports",
            count: report_count,
            navigate: ~p"/cases/#{case_id}/reports"
          },
        %{id: :cve, label: "CVE", navigate: ~p"/cases/#{case_id}/cve"},
        %{id: :osv, label: "OSV", navigate: ~p"/cases/#{case_id}/osv"},
        %{id: :advisory, label: "Advisory", navigate: ~p"/cases/#{case_id}/advisory"},
        %{id: :github, label: "GitHub", navigate: ~p"/cases/#{case_id}/github"},
        %{id: :publication, label: "Publication", navigate: ~p"/cases/#{case_id}/publication"}
      ],
      & &1
    )
  end

  # The aggregate sums the notification rows that are still unread, so it is
  # nil both for a case with nothing new and for the author of everything in
  # it.
  defp unseen_label(count) when is_integer(count) and count > 0 do
    "#{count} new #{if count == 1, do: "comment", else: "comments"}"
  end

  defp unseen_label(_none), do: nil

  # The public page serves `:published` records only, so a link for any other
  # state would land on a 404.
  @doc "The public CVE page of the case, or nil while there is none."
  def public_cve_href(%{cve_id: cve_id, cve_record: %{state: :published}}) when is_binary(cve_id),
    do: ~p"/cves/#{cve_id <> ".html"}"

  def public_cve_href(_case_record), do: nil

  defp load_case(socket, load) do
    case Cases.get_case(socket.assigns.case_id, actor: socket.assigns.current_user, load: load) do
      {:ok, case_record} -> case_record
      {:error, _error} -> nil
    end
  end

  # nil: the case vanished or became inaccessible (on mount and refetch alike).
  defp fetched(nil, socket, _after_fetch, _marks_read) do
    socket |> put_flash(:error, "Case not found.") |> push_navigate(to: ~p"/cases")
  end

  defp fetched(case_record, socket, after_fetch, marks_read) do
    actor = socket.assigns.current_user

    {case_record, socket} =
      if connected?(socket) do
        Notifications.mark_case_notifications_read!(case_record.id, %{kinds: marks_read},
          ## ------------------------------------------------------------------ events
          actor: actor
        )

        # The case was read before those rows were, so what it says is unseen
        # is what was unseen on the way in. `keep_live` has already assigned
        # it, so the reloaded one has to take its place.
        case_record =
          Ash.load!(case_record, [:unseen_comment_count], actor: actor, reuse_values?: false)

        {case_record, assign(socket, :case_record, case_record)}
      else
        {case_record, socket}
      end

    after_fetch.(case_record, socket)
  end

  defp handle_event("lifecycle", %{"action" => action}, socket)
       when action in ~w(request_review request_changes approve reopen triage accept withdraw) do
    {fun, done} = lifecycle_action(action)

    socket =
      case fun.(socket.assigns.case_record, actor: socket.assigns.current_user) do
        {:ok, _case_record} -> put_flash(socket, :info, done)
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  defp handle_event("open_lifecycle_modal", %{"modal" => modal}, socket) when is_map_key(@form_modals, modal) do
    {:halt, assign(socket, :lifecycle_modal, Map.fetch!(@form_modals, modal))}
  end

  defp handle_event("open_lifecycle_modal", %{"modal" => "merge"}, socket) do
    {:halt, assign(socket, :lifecycle_modal, {:merge, merge_search(socket, "")})}
  end

  defp handle_event("search_merge_target", params, socket) do
    search = merge_search(socket, params["query"], params["into_case_id"])

    {:halt, assign(socket, :lifecycle_modal, {:merge, search})}
  end

  # Opening the picker reads the pool fresh: the ID list is the one thing on
  # this page that another POC can invalidate between page load and click.
  defp handle_event("open_lifecycle_modal", %{"modal" => "cve"}, socket) do
    records = CVE.list_assignable_cve_records!(actor: socket.assigns.current_user)

    {:halt, assign(socket, :lifecycle_modal, {:cve, records})}
  end

  defp handle_event("close_lifecycle_modal", _params, socket) do
    {:halt, assign(socket, :lifecycle_modal, nil)}
  end

  defp handle_event("reject_case", params, socket) do
    args = %{closed_reason: presence(params["closed_reason"])}

    case Cases.reject_case(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
      {:ok, _case_record} -> {:halt, done(socket, "Case rejected.")}
      {:error, error} -> {:halt, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  defp handle_event("split_case", %{"title" => title}, socket) do
    case Cases.split_case(socket.assigns.case_record.id, %{title: title}, actor: socket.assigns.current_user) do
      {:ok, split} -> {:halt, push_navigate(socket, to: ~p"/cases/#{split.id}")}
      {:error, error} -> {:halt, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  defp handle_event("confirm_merge", %{"into_case_id" => into_case_id}, socket) do
    case Cases.merge_case(socket.assigns.case_record, into_case_id, actor: socket.assigns.current_user) do
      {:ok, _merged} -> {:halt, push_navigate(socket, to: ~p"/cases/#{into_case_id}")}
      {:error, error} -> {:halt, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  # Both paths land here: "next free ID" sends no cve_record_id and lets the
  # action pick, a chosen row sends the one it names.
  defp handle_event("confirm_assign_cve_id", params, socket) do
    args =
      case params["cve_record_id"] do
        id when is_binary(id) and id != "" -> %{cve_record_id: id}
        _blank -> %{}
      end

    socket =
      case Cases.assign_case_cve_id(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
        {:ok, _case_record} ->
          assign(socket, :lifecycle_modal, nil)

        {:error, error} ->
          put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  defp handle_event("link_upstream_cve", %{"cve_id" => cve_id}, socket) do
    socket =
      case Cases.link_case_upstream_cve(
             socket.assigns.case_record,
             String.trim(cve_id),
             actor: socket.assigns.current_user
           ) do
        {:ok, _case_record} -> assign(socket, :lifecycle_modal, nil)
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:halt, socket}
  end

  defp handle_event("close_case", params, socket) do
    args = %{
      closed_reason: params["closed_reason"],
      reject_cve_id: params["cve_decision"] == "reject"
    }

    case Cases.close_case(socket.assigns.case_record, args, actor: socket.assigns.current_user) do
      {:ok, _case_record} -> {:halt, done(socket, "Case closed.")}
      {:error, error} -> {:halt, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  # A second click on an emoji the actor gave takes it back.
  defp handle_event("toggle_reaction", %{"comment_id" => comment_id, "reaction" => reaction}, socket) do
    actor = socket.assigns.current_user
    case_record = socket.assigns.case_record

    with {:ok, emoji} <- Emoji.match(reaction),
         comments when is_list(comments) <- case_record.comments,
         %{} = comment <- Enum.find(comments, &(&1.id == comment_id)) do
      result =
        case Enum.find(comment.reactions, &(&1.user_id == actor.id and &1.emoji == emoji)) do
          nil ->
            Cases.react_to_case_comment(
              %{comment_id: comment.id, emoji: emoji},
              actor: actor
            )

          reaction ->
            Cases.take_back_case_comment_reaction(reaction, actor: actor)
        end

      case result do
        {:error, error} -> {:halt, put_flash(socket, :error, errors_to_string(error))}
        _done -> {:halt, socket}
      end
    else
      _unknown -> {:halt, socket}
    end
  end

  defp handle_event(_event, _params, socket), do: {:cont, socket}

  defp lifecycle_action("request_review"), do: {&Cases.request_case_review/2, "Review requested."}

  defp lifecycle_action("request_changes"), do: {&Cases.request_case_changes/2, "Changes requested."}

  defp lifecycle_action("approve"), do: {&Cases.approve_case/2, "Case approved."}
  defp lifecycle_action("reopen"), do: {&Cases.reopen_case/2, "Case reopened."}
  defp lifecycle_action("triage"), do: {&Cases.triage_case/2, "Case marked under triage."}
  defp lifecycle_action("accept"), do: {&Cases.accept_case/2, "Case accepted."}
  defp lifecycle_action("withdraw"), do: {&Cases.withdraw_case/2, "Report withdrawn."}

  # The cases this one may merge into: open ones the actor can read, matched
  # as the board search matches them.
  defp merge_search(socket, query, selected \\ nil) do
    ## -------------------------------------------------------------- components
    query = String.trim(query || "")
    case_id = socket.assigns.case_record.id

    base =
      Case
      |> Ash.Query.filter(id != ^case_id and state not in [:closed, :merged])
      |> Ash.Query.limit(@merge_picker_limit + 1)

    base =
      if query == "",
        do: base,
        else: Ash.Query.filter(base, matches_query(query: ^String.downcase(query)))

    {cases, rest} =
      [actor: socket.assigns.current_user, load: [:cve_id], query: base]
      |> Cases.list_cases!()
      |> Enum.split(@merge_picker_limit)

    %{
      query: query,
      cases: cases,
      more?: rest != [],
      selected: Enum.find_value(cases, &(&1.id == selected && selected))
    }
  end

  defp done(socket, message) do
    socket |> assign(:lifecycle_modal, nil) |> put_flash(:info, message)
  end

  defp presence(nil), do: nil
  defp presence(value), do: if(String.trim(value) == "", do: nil, else: value)

  @actions ~w(accept triage withdraw assign_cve_id request_review request_changes approve publish
              reopen split merge reject close)a

  @doc """
  Renders the lifecycle actions the actor may take on the case. Publishing is
  a link: the act belongs on the Publication tab, next to its validation.
  """
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :active_tab, :atom, default: nil, doc: "the tab being rendered"

  def lifecycle_actions(assigns) do
    %{case_record: case_record, current_user: actor, active_tab: active_tab} = assigns

    assigns =
      assign(
        assigns,
        :actions,
        Enum.filter(@actions, &offered?(&1, actor, case_record, active_tab))
      )

    ~H"""
    <.case_actions actions={@actions} publish_href={~p"/cases/#{@case_record.id}/publication"} />
    """
  end

  defp offered?(:accept, actor, case_record, _tab), do: Cases.can_accept_case?(actor, case_record, validate?: true)

  defp offered?(:triage, actor, case_record, _tab), do: Cases.can_triage_case?(actor, case_record, validate?: true)

  defp offered?(:withdraw, actor, case_record, _tab), do: Cases.can_withdraw_case?(actor, case_record, validate?: true)

  defp offered?(:assign_cve_id, actor, case_record, _tab),
    do: Cases.can_assign_case_cve_id?(actor, case_record, validate?: true)

  defp offered?(:request_review, actor, case_record, _tab),
    do: Cases.can_request_case_review?(actor, case_record, validate?: true)

  defp offered?(:request_changes, actor, case_record, _tab),
    do: Cases.can_request_case_changes?(actor, case_record, validate?: true)

  defp offered?(:approve, actor, case_record, _tab), do: Cases.can_approve_case?(actor, case_record, validate?: true)

  defp offered?(:publish, _actor, _case_record, :publication), do: false

  defp offered?(:publish, actor, case_record, _tab), do: Cases.can_publish_case?(actor, case_record, validate?: true)

  defp offered?(:reopen, actor, case_record, _tab), do: Cases.can_reopen_case?(actor, case_record, validate?: true)

  defp offered?(:split, actor, case_record, _tab), do: Cases.can_split_case?(actor, case_record.id, %{}, validate?: true)

  defp offered?(:merge, actor, case_record, _tab),
    do: Cases.can_merge_case?(actor, case_record, case_record.id, validate?: false)

  defp offered?(:reject, actor, case_record, _tab), do: Cases.can_reject_case?(actor, case_record, validate?: true)

  defp offered?(:close, actor, case_record, _tab), do: Cases.can_close_case?(actor, case_record, validate?: true)

  @doc """
  Renders the open lifecycle modal, the `:lifecycle_modal` assign `mount/3`
  sets, or nothing while none is open.
  """
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :modal, :any, required: true, doc: "the `:lifecycle_modal` assign"

  def lifecycle_modal(%{modal: nil} = assigns), do: ~H""

  def lifecycle_modal(%{modal: :split} = assigns) do
    ~H"""
    <.modal id="split-case-modal" title="Split off a finding" on_cancel="close_lifecycle_modal">
      <form id="split-case-form" phx-submit="split_case" class="space-y-3">
        <input
          type="text"
          name="title"
          phx-mounted={JS.focus()}
          required
          placeholder="Title of the new case"
          aria-label="Title of the new case"
          class="input input-bordered input-sm w-full"
        />
        <p class="text-sm text-base-content/60">
          The new case cites the same reports and gives the same people access.
        </p>
        <div class="modal-action">
          <button type="button" phx-click="close_lifecycle_modal" class="btn btn-ghost btn-sm">
            Cancel
          </button>
          <button type="submit" class="btn btn-sm btn-eef">Split</button>
        </div>
      </form>
    </.modal>
    """
  end

  def lifecycle_modal(%{modal: :reject} = assigns) do
    ~H"""
    <.modal id="reject-case-modal" title="Reject case" on_cancel="close_lifecycle_modal">
      <form id="reject-case-form" phx-submit="reject_case" class="space-y-3">
        <input
          type="text"
          name="closed_reason"
          phx-mounted={JS.focus()}
          placeholder="Why does the CNA decline this case?"
          aria-label="Reason"
          class="input input-bordered input-sm w-full"
        />
        <p class="text-sm text-base-content/60">
          Rejecting closes the case and withdraws its open invites.
        </p>
        <div class="modal-action">
          <button type="button" phx-click="close_lifecycle_modal" class="btn btn-ghost btn-sm">
            Cancel
          </button>
          <button type="submit" class="btn btn-sm btn-error">Reject case</button>
        </div>
      </form>
    </.modal>
    """
  end

  def lifecycle_modal(%{modal: :close} = assigns) do
    ~H"""
    <.modal id="close-case-modal" title="Close case" on_cancel="close_lifecycle_modal">
      <form id="close-case-form" phx-submit="close_case" class="space-y-3">
        <input
          type="text"
          name="closed_reason"
          phx-mounted={JS.focus()}
          placeholder="Why is this case being closed?"
          aria-label="Reason"
          class="input input-bordered input-sm w-full"
        />
        <div :if={@case_record.cve_id && Map.get(@case_record, :upstream_cve)} class="text-sm">
          <input type="hidden" name="cve_decision" value="release" />
          <p>
            {@case_record.cve_id} is an upstream CVE that another CNA owns. Closing unlinks it
            unless this CNA's enrichment is already published.
          </p>
        </div>
        <div
          :if={@case_record.cve_id && !Map.get(@case_record, :upstream_cve)}
          class="text-sm space-y-1"
        >
          <p class="font-semibold">{@case_record.cve_id} is assigned to this case:</p>
          <label class="flex items-center gap-2">
            <input type="radio" name="cve_decision" value="reject" class="radio radio-sm" required />
            Reject (burn) the CVE ID at MITRE
          </label>
          <label class="flex items-center gap-2">
            <input type="radio" name="cve_decision" value="release" class="radio radio-sm" />
            Return the ID to the pool
          </label>
        </div>
        <p class="text-sm text-base-content/60">Closing is terminal.</p>
        <div class="modal-action">
          <button type="button" phx-click="close_lifecycle_modal" class="btn btn-ghost btn-sm">
            Cancel
          </button>
          <button type="submit" class="btn btn-sm btn-error">Close case</button>
        </div>
      </form>
    </.modal>
    """
  end

  def lifecycle_modal(%{modal: {:merge, search}} = assigns) do
    assigns = assign(assigns, :search, search)

    ~H"""
    <.modal id="merge-picker" title="Merge into another case" on_cancel="close_lifecycle_modal">
      <p class="text-sm text-base-content/60 -mt-1 mb-4">
        The other case then cites this case's reports and gives access to everyone on this case.
        This case ends as merged.
      </p>
      <form
        id="merge-case-form"
        phx-change="search_merge_target"
        phx-submit="confirm_merge"
        class="space-y-3"
      >
        <.case_picker
          id="merge-target-picker"
          name="into_case_id"
          query={@search.query}
          cases={@search.cases}
          selected={@search.selected}
          more?={@search.more?}
        />
        <div class="modal-action">
          <button type="button" phx-click="close_lifecycle_modal" class="btn btn-ghost btn-sm">
            Cancel
          </button>
          <button type="submit" class="btn btn-sm btn-eef" disabled={@search.cases == []}>
            Merge
          </button>
        </div>
      </form>
    </.modal>
    """
  end

  def lifecycle_modal(%{modal: {:cve, records}} = assigns) do
    assigns = assign(assigns, :records, records)

    ~H"""
    <.cve_picker_modal case_record={@case_record} current_user={@current_user} records={@records} />
    """
  end

  # The CVE ID picker for a case that has none.
  #
  # Two ways to take an ID, kept visibly apart: the top half is the one-click
  # default (whatever is next in the pool), the bottom half is the deliberate
  # pick. Nothing is assigned by opening this. Both halves need their own
  # button, so neither path can be taken by reflex.
  #
  # Only a caller who may name a record can see the pool (the reservations are
  # unreadable to anyone else), so for everyone else the listing is absent and
  # the top half says nothing about what is in it. An empty `records` there
  # means "not visible", not "not there".
  attr :case_record, :map, required: true
  attr :current_user, :map, required: true
  attr :records, :list, required: true

  defp cve_picker_modal(assigns) do
    {free, withheld} = Enum.split_with(assigns.records, &(&1.state == :reserved))

    can_choose? =
      Cases.can_assign_case_cve_id?(
        assigns.current_user,
        assigns.case_record,
        %{cve_record_id: Ash.UUID.generate()},
        validate?: false
      )

    can_link_upstream? =
      Cases.can_link_case_upstream_cve?(
        assigns.current_user,
        assigns.case_record,
        "CVE-0000-0000",
        validate?: false
      )

    assigns =
      assign(assigns,
        free: free,
        withheld: withheld,
        can_choose?: can_choose?,
        can_link_upstream?: can_link_upstream?
      )

    ~H"""
    <.modal id="cve-picker-modal" title="Assign a CVE ID" on_cancel="close_lifecycle_modal">
      <div class="space-y-4">
        <div class="rounded-lg border border-base-300 bg-base-200 p-3">
          <p class="text-sm font-semibold">Take the next free ID</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            <span :if={!@can_choose? or @free != []}>
              The lowest free ID of the current year, chosen when you confirm.
            </span>
            <span :if={@can_choose? and @free == []}>
              The pool is empty — reserve more IDs first.
            </span>
          </p>
          <button
            :if={!@can_choose? or @free != []}
            type="button"
            class="btn btn-eef btn-sm mt-2"
            phx-click="confirm_assign_cve_id"
          >
            Assign the next free ID
          </button>
        </div>

        <form
          :if={@can_choose? and (@free != [] or @withheld != [])}
          id="choose-cve-id"
          phx-submit="confirm_assign_cve_id"
          class="rounded-lg border border-base-300 p-3"
        >
          <p class="text-sm font-semibold">Or choose a specific ID</p>
          <div class="mt-2 max-h-64 overflow-y-auto space-y-1">
            <label
              :for={record <- @free}
              class="flex items-center gap-2 py-0.5 cursor-pointer text-sm"
            >
              <input
                type="radio"
                name="cve_record_id"
                value={record.id}
                class="radio radio-sm"
                required
              />
              <span class="font-mono text-xs">{record.cve_id}</span>
              <span class="text-xs text-base-content/50 tabular-nums">
                reserved {format_date(record.reserved_at)}
              </span>
            </label>

            <%!-- Withheld IDs are held for something outside this system, so
                  they sit below a divider with the reason attached: taking one
                  should read as overriding a decision, not picking off a list. --%>
            <div
              :if={@withheld != []}
              class="flex items-center gap-2 pt-2 text-[0.66rem] font-semibold uppercase tracking-wider text-warning"
            >
              <span class="h-px flex-1 bg-warning/30"></span>
              withheld <span class="h-px flex-1 bg-warning/30"></span>
            </div>
            <label
              :for={record <- @withheld}
              class="flex items-start gap-2 py-1 px-2 -mx-1 rounded-md cursor-pointer text-sm bg-warning/10 border border-warning/25"
            >
              <input
                type="radio"
                name="cve_record_id"
                value={record.id}
                class="radio radio-sm radio-warning mt-0.5"
                required
              />
              <span class="flex flex-col">
                <span class="flex items-baseline gap-2">
                  <span class="font-mono text-xs">{record.cve_id}</span>
                  <span class="text-xs text-warning tabular-nums">
                    withheld {format_date(record.withheld_at)}
                  </span>
                </span>
                <span class="text-xs text-base-content/60">{record.withhold_reason}</span>
              </span>
            </label>
          </div>
          <button type="submit" class="btn btn-eef-quiet btn-sm mt-3">
            Assign chosen ID
          </button>
        </form>

        <p
          :if={@can_choose? and @free == [] and @withheld == []}
          class="text-sm text-base-content/60"
        >
          No CVE IDs are available to assign.
        </p>

        <form
          :if={@can_link_upstream?}
          id="link-upstream-cve"
          phx-submit="link_upstream_cve"
          class="rounded-lg border border-info/40 bg-info/5 p-3"
        >
          <p class="text-sm font-semibold">Or link an upstream CVE</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            For a vulnerability in code a package vendors from a project outside this CNA's
            scope. The CNA rules forbid this CNA to assign a CVE for it: the CNA responsible
            for that project assigns it. Publishing adds this CNA's enrichment to the
            upstream record as an ADP container and sends nothing to MITRE. A RESERVED ID
            can be linked during an embargo. Publishing waits until its CNA publishes it.
          </p>
          <div class="mt-2 flex gap-2">
            <input
              type="text"
              name="cve_id"
              required
              pattern="CVE-\d{4}-\d{4,19}"
              placeholder="CVE-2026-12345"
              aria-label="Upstream CVE ID"
              class="input input-bordered input-sm w-48 font-mono"
            />
            <button type="submit" class="btn btn-eef-quiet btn-sm">Link upstream CVE</button>
          </div>
        </form>
      </div>

      <:actions>
        <button type="button" class="btn btn-ghost btn-sm" phx-click="close_lifecycle_modal">
          Cancel
        </button>
      </:actions>
    </.modal>
    """
  end
end
