# SPDX-FileCopyrightText: 2026 Erlang Ecosystem Foundation
#
# SPDX-License-Identifier: Apache-2.0

defmodule VarselWeb.ReportTriageLive do
  @moduledoc """
  Vulnerability reports, in the two shapes the same route serves.

  For a POC this is the triage queue: list inbound reports, mark them under
  triage, reject them, or accept them into a case — either a fresh draft case
  (titled from the report summary) or an existing open case, completing the
  report → case intake path. Accepting navigates straight to the case
  workspace.

  For any other reporter it is a simplified list of their own reports (summary
  and current status only) — the `:list_reports` read policy does the scoping.
  They cannot triage, but may withdraw a report the CNA has not picked up yet.

  Both shapes are the console's one-wide-column list (`list_card` under
  `scope_tab`s), not the case board's lanes: a report is mostly a body of
  prose, and prose wants the width a lane cannot give it.
  """
  use VarselWeb, :live_view

  import AshPhoenix.LiveView, only: [keep_live: 4]
  import VarselWeb.CaseComponents, only: [relative_timestamp: 1, report_payload: 1]
  import VarselWeb.UserComponents, only: [user_badge: 1]

  alias Varsel.Cases
  alias Varsel.CVE
  alias Varsel.CVE.VulnerabilityReport

  @impl Phoenix.LiveView
  def mount(_params, _session, socket) do
    # The page is both a triage queue and a reporter's own list; which one it
    # is follows from whether triaging is something you may do at all.
    triage? = Ash.can?({VulnerabilityReport, :triage}, socket.assigns.current_user)

    socket =
      socket
      |> assign(
        page_title: if(triage?, do: "Report Triage", else: "My Reports"),
        triage?: triage?,
        filter: "open",
        expanded_payloads: MapSet.new(),
        # The decision being taken, as {report_id, :accept | :triage | :reject}.
        deciding: nil
      )
      |> keep_live(:reports, &list_reports/1,
        subscribe: "vulnerability_report:all",
        results: :lose
      )

    {:ok, if(triage?, do: assign_open_cases(socket), else: socket)}
  end

  @impl Phoenix.LiveView
  def handle_event("filter", %{"filter" => filter}, socket) do
    {:noreply, assign(socket, filter: filter)}
  end

  def handle_event("toggle_payload", %{"report_id" => report_id}, socket) do
    expanded = socket.assigns.expanded_payloads

    expanded =
      if MapSet.member?(expanded, report_id) do
        MapSet.delete(expanded, report_id)
      else
        MapSet.put(expanded, report_id)
      end

    {:noreply, assign(socket, :expanded_payloads, expanded)}
  end

  def handle_event("decide", %{"report_id" => report_id, "decision" => decision}, socket) do
    {:noreply, assign(socket, deciding: {report_id, String.to_existing_atom(decision)})}
  end

  def handle_event("cancel_decision", _params, socket) do
    {:noreply, assign(socket, deciding: nil)}
  end

  def handle_event("triage", %{"report_id" => report_id, "triage_notes" => notes}, socket) do
    act(socket, report_id, "marked under triage", fn report, actor ->
      CVE.triage_vulnerability_report(report, %{triage_notes: presence(notes)}, actor: actor)
    end)
  end

  def handle_event("reject", %{"report_id" => report_id, "triage_notes" => notes}, socket) do
    act(socket, report_id, "rejected", fn report, actor ->
      CVE.reject_vulnerability_report(report, %{triage_notes: presence(notes)}, actor: actor)
    end)
  end

  def handle_event("accept", %{"report_id" => report_id} = params, socket) do
    report = find_report(socket, report_id)
    args = %{case_id: presence(params["case_id"]), triage_notes: presence(params["triage_notes"])}

    case CVE.accept_vulnerability_report(report, args, actor: socket.assigns.current_user) do
      {:ok, accepted} ->
        {:noreply,
         socket
         |> put_flash(:info, "Report accepted into a case.")
         |> push_navigate(to: ~p"/cases/#{accepted.case_id}")}

      {:error, error} ->
        {:noreply, put_flash(socket, :error, errors_to_string(error))}
    end
  end

  def handle_event("withdraw", %{"report_id" => report_id}, socket) do
    act(socket, report_id, "withdrawn", fn report, actor ->
      CVE.withdraw_vulnerability_report(report, actor: actor)
    end)
  end

  defp act(socket, report_id, verb, fun) do
    socket =
      case fun.(find_report(socket, report_id), socket.assigns.current_user) do
        # The list refreshes via the pub_sub notification handled above.
        {:ok, _report} -> socket |> put_flash(:info, "Report #{verb}.") |> assign(deciding: nil)
        {:error, error} -> put_flash(socket, :error, errors_to_string(error))
      end

    {:noreply, socket}
  end

  defp find_report(socket, report_id) do
    Enum.find(socket.assigns.reports, &(&1.id == report_id))
  end

  # Empty when nothing is being decided, or when the report left the list
  # because someone else resolved it while the box stood open over it.
  defp deciding_report(_reports, nil), do: []

  defp deciding_report(reports, {report_id, _decision}) do
    Enum.filter(reports, &(&1.id == report_id))
  end

  defp list_reports(socket) do
    CVE.list_vulnerability_reports!(
      actor: socket.assigns.current_user,
      load: [:participants, reporter: [:display_name, :avatar_url]]
    )
  end

  # Open (non-closed) cases a report can be consolidated into.
  defp assign_open_cases(socket) do
    cases =
      [actor: socket.assigns.current_user, load: [:cve_id]]
      |> Cases.list_cases!()
      |> Enum.reject(&(&1.state == :closed))

    assign(socket, :open_cases, cases)
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value), do: if(String.trim(value) == "", do: nil, else: value)

  defp state_dot_class(:submitted), do: "bg-warning"
  defp state_dot_class(:triaged), do: "bg-info"
  defp state_dot_class(:accepted), do: "bg-success"
  defp state_dot_class(:rejected), do: "bg-error"
  defp state_dot_class(_other), do: "bg-base-content/30"

  defp state_text_class(:submitted), do: "text-warning"
  defp state_text_class(:triaged), do: "text-info"
  defp state_text_class(:accepted), do: "text-success"
  defp state_text_class(:rejected), do: "text-base-content/50"
  defp state_text_class(_other), do: "text-base-content/60"

  defp actionable?(state), do: state in [:submitted, :triaged]

  # A participant naming the reporter means they have not signed in yet.
  # Without one, a missing reporter is an account that went away.
  defp reporter_known?(%{reporter: nil} = report) do
    not Enum.any?(report.participants, &(&1.role == :reporter))
  end

  defp reporter_known?(_report), do: true

  # Whether the triage block has anything to show; each form inside asks about
  # its own action, so this only decides the spacing around them.
  defp triage_actions?(actor, report) do
    CVE.can_accept_vulnerability_report?(actor, report, %{}, validate?: true) or
      CVE.can_triage_vulnerability_report?(actor, report, %{}, validate?: true) or
      CVE.can_reject_vulnerability_report?(actor, report, %{}, validate?: true)
  end

  # The triage queue defaults to the reports still needing action; resolved
  # reports stay reachable behind their own tabs.
  defp visible_reports(reports, "open"), do: Enum.filter(reports, &actionable?(&1.state))
  defp visible_reports(reports, "accepted"), do: Enum.filter(reports, &(&1.state == :accepted))
  defp visible_reports(reports, "rejected"), do: Enum.filter(reports, &(&1.state == :rejected))
  defp visible_reports(reports, _all), do: reports

  @scopes [
    {"open", "Open", "bg-warning"},
    {"accepted", "Accepted", "bg-success"},
    {"rejected", "Rejected", "bg-error"},
    {"all", "All reports", nil}
  ]

  defp tile_options(reports) do
    for {filter, label, dot} <- @scopes do
      %{value: filter, label: label, count: length(visible_reports(reports, filter)), dot: dot}
    end
  end

  defp scopes, do: @scopes

  defp case_label(case_record) do
    [case_record.cve_id, case_record.title || "Untitled"]
    |> Enum.reject(&is_nil/1)
    |> Enum.join(" — ")
  end

  @impl Phoenix.LiveView
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user} current_path={@current_path}>
      <.page_header>
        <:eyebrow>CNA Console</:eyebrow>
        <:title>{if @triage?, do: "Report Triage", else: "My Reports"}</:title>
        <:subtitle :if={@triage?}>
          Inbound vulnerability reports: triage, accept into a case, or reject.
        </:subtitle>
        <:subtitle :if={not @triage?}>
          Reports you submitted. The CNA team triages every report and follows up with you once it
          has been reviewed.
        </:subtitle>
        <:actions>
          <.link navigate={~p"/report"} class="btn btn-sm btn-eef">Submit a report</.link>
        </:actions>
      </.page_header>

      <.page_container>
        <div :if={@triage?} class="mb-4">
          <.stat_tiles active={@filter} options={tile_options(@reports)} />
        </div>

        <.list_card empty?={visible_reports(@reports, active_filter(@triage?, @filter)) == []}>
          <:tabs :if={@triage?}>
            <.scope_button
              :for={{value, label, _dot} <- scopes()}
              active={@filter}
              value={value}
              label={label}
              count={length(visible_reports(@reports, value))}
            />
          </:tabs>
          <:note :if={not @triage?}>
            <.count_label count={length(@reports)} singular="report" />
          </:note>
          <:empty>{empty_sentence(@triage?, @reports, @filter)}</:empty>

          <.report_row
            :for={report <- visible_reports(@reports, active_filter(@triage?, @filter))}
            report={report}
            triage?={@triage?}
            current_user={@current_user}
            payload_open?={MapSet.member?(@expanded_payloads, report.id)}
          />
        </.list_card>

        <.decision_modal
          :for={report <- deciding_report(@reports, @deciding)}
          report={report}
          decision={elem(@deciding, 1)}
          open_cases={@open_cases}
        />
      </.page_container>
    </Layouts.app>
    """
  end

  # A reporter has no scopes to pick from, so their list is always "all".
  defp active_filter(true = _triage?, filter), do: filter
  defp active_filter(false = _triage?, _filter), do: "all"

  defp empty_sentence(false = _triage?, _reports, _filter), do: "You have not submitted any reports yet."

  defp empty_sentence(true = _triage?, [], _filter), do: "No reports here."
  defp empty_sentence(true = _triage?, _reports, "open"), do: "No reports waiting for triage."
  defp empty_sentence(true = _triage?, _reports, _filter), do: "No reports here."

  attr :active, :string, required: true
  attr :value, :string, required: true
  attr :label, :string, required: true
  attr :count, :integer, required: true

  # A scope is a filter, not a resort: the list narrows in place, so the scope
  # lives in the view rather than the URL and this is a button.
  defp scope_button(assigns) do
    assigns = assign(assigns, :active?, assigns.active == assigns.value)

    ~H"""
    <button type="button" phx-click="filter" phx-value-filter={@value}>
      <.scope_tab active?={@active?} label={@label} count={@count} />
    </button>
    """
  end

  attr :report, :any, required: true
  attr :triage?, :boolean, required: true
  attr :current_user, :any, required: true
  attr :payload_open?, :boolean, required: true

  # One report as a row of the list card: who said what and when, the body
  # they wrote, and — for whoever may act on it — the decision bar at its
  # foot. Resolved rows quiet down; only the open ones carry weight.
  defp report_row(assigns) do
    ~H"""
    <article class={[
      "border-b border-base-300 last:border-0 px-4 py-3.5",
      not actionable?(@report.state) && "bg-base-300/20"
    ]}>
      <div class="flex items-start justify-between gap-4">
        <div class="min-w-0">
          <h3 class={[
            "font-semibold leading-snug",
            not actionable?(@report.state) && "text-base-content/70"
          ]}>
            {@report.summary}
          </h3>
          <div class="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 mt-0.5 text-xs text-base-content/60">
            <.user_badge
              :if={@triage? and reporter_known?(@report)}
              user={@report.reporter}
              class="items-center"
              name_class="text-base-content/60"
            />
            <span :if={@triage? and reporter_known?(@report)}>·</span>
            <.relative_timestamp at={@report.inserted_at} />
          </div>
        </div>

        <div class="flex items-center gap-3 shrink-0">
          <.state
            dot={state_dot_class(@report.state)}
            class={["text-sm", state_text_class(@report.state)]}
          >
            {Phoenix.Naming.humanize(@report.state)}
          </.state>
          <button
            :if={CVE.can_withdraw_vulnerability_report?(@current_user, @report, %{}, validate?: true)}
            type="button"
            phx-click="withdraw"
            phx-value-report_id={@report.id}
            class="btn btn-outline btn-error btn-xs"
            data-confirm="Withdraw this report? The CNA team will stop triaging it."
          >
            Withdraw
          </button>
        </div>
      </div>

      <%!-- Scroll-capped: one verbose report must not push every other row
            off the queue. --%>
      <div :if={@triage?} class="mt-2.5">
        <.report_payload
          payload={@report.report_json}
          report_id={@report.id}
          expanded?={@payload_open?}
          toggle="toggle_payload"
          body_class="max-h-56 overflow-y-auto"
        />
      </div>

      <div :if={@triage? and @report.participants != []} class="mt-2.5">
        <p class="text-xs font-semibold text-base-content/60">
          Named by the sender
        </p>
        <ul class="mt-1 space-y-0.5 text-xs">
          <li
            :for={participant <- @report.participants}
            class="flex flex-wrap items-center gap-x-2 text-base-content/70"
          >
            <span class="badge badge-ghost badge-sm">{participant.role}</span>
            <span class="font-mono">{participant.username}</span>
            <span :if={participant.email} class="text-base-content/50">{participant.email}</span>
          </li>
        </ul>
      </div>

      <p :if={@report.triage_notes} class="mt-2 text-sm text-base-content/70 italic">
        {@report.triage_notes}
      </p>

      <.link
        :if={@triage? and @report.case_id}
        navigate={~p"/cases/#{@report.case_id}"}
        class="link link-hover text-primary text-sm font-medium inline-block mt-2"
      >
        View the case this report became →
      </.link>

      <.decision_bar
        :if={triage_actions?(@current_user, @report)}
        report={@report}
        current_user={@current_user}
      />
    </article>
    """
  end

  attr :report, :any, required: true
  attr :current_user, :any, required: true

  defp decision_bar(assigns) do
    ~H"""
    <div class="flex flex-wrap items-center gap-2 mt-3 pt-3 border-t border-base-300">
      <button
        :if={CVE.can_accept_vulnerability_report?(@current_user, @report, %{}, validate?: true)}
        type="button"
        phx-click="decide"
        phx-value-report_id={@report.id}
        phx-value-decision="accept"
        class="btn btn-eef btn-sm"
      >
        Accept into case
      </button>
      <button
        :if={CVE.can_triage_vulnerability_report?(@current_user, @report, %{}, validate?: true)}
        type="button"
        phx-click="decide"
        phx-value-report_id={@report.id}
        phx-value-decision="triage"
        class="btn btn-ghost btn-sm border border-base-300"
      >
        Under triage
      </button>
      <button
        :if={CVE.can_reject_vulnerability_report?(@current_user, @report, %{}, validate?: true)}
        type="button"
        phx-click="decide"
        phx-value-report_id={@report.id}
        phx-value-decision="reject"
        class="btn btn-error btn-outline btn-sm ml-auto"
      >
        Reject
      </button>
    </div>
    """
  end

  attr :report, :any, required: true
  attr :decision, :atom, required: true, values: [:accept, :triage, :reject]
  attr :open_cases, :list, required: true

  defp decision_modal(assigns) do
    ~H"""
    <.modal id={"decide-#{@report.id}"} title={decision_title(@decision)} on_cancel="cancel_decision">
      <p class="text-sm text-base-content/60 -mt-1 mb-4">{@report.summary}</p>

      <form id={"decision-form-#{@report.id}"} phx-submit={to_string(@decision)} class="space-y-3">
        <input type="hidden" name="report_id" value={@report.id} />

        <label :if={@decision == :accept} class="block">
          <span class="label mb-1">Case</span>
          <select name="case_id" class="w-full select select-bordered select-sm">
            <option value="">New draft case from this report</option>
            <option :for={case_record <- @open_cases} value={case_record.id}>
              {case_label(case_record)}
            </option>
          </select>
        </label>

        <label class="block">
          <span class="label mb-1">{note_label(@decision)}</span>
          <input
            type="text"
            name="triage_notes"
            autocomplete="off"
            placeholder={note_placeholder(@decision)}
            class="w-full input input-bordered input-sm"
          />
        </label>

        <div class="modal-action">
          <button type="button" phx-click="cancel_decision" class="btn btn-ghost btn-sm">
            Cancel
          </button>
          <button type="submit" class={["btn btn-sm", decision_class(@decision)]}>
            {decision_commit(@decision)}
          </button>
        </div>
      </form>
    </.modal>
    """
  end

  defp decision_title(:accept), do: "Accept into a case"
  defp decision_title(:triage), do: "Mark under triage"
  defp decision_title(:reject), do: "Reject this report"

  defp decision_commit(:accept), do: "Accept"
  defp decision_commit(:triage), do: "Mark under triage"
  defp decision_commit(:reject), do: "Reject"

  defp decision_class(:accept), do: "btn-eef"
  defp decision_class(:triage), do: "btn-primary"
  defp decision_class(:reject), do: "btn-error"

  defp note_label(:reject), do: "Reason"
  defp note_label(_decision), do: "Notes (optional)"

  defp note_placeholder(:accept), do: "What the CNA should know about this report"
  defp note_placeholder(:triage), do: "What is being looked into"
  defp note_placeholder(:reject), do: "Why is this rejected?"
end
